using CK.Core;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// What this local party trusts of one remote: the pinned event of the remote's key event log, and
/// the replay cache of the nonces it sent.
/// <para>
/// The pin is stored as <c>Identity.{Seq}.trust</c> in the remote's shared folder (the encoded event).
/// The sequence is in the name on purpose: that folder is shared by every local party of the file
/// system, across processes, and two processes that apply different rotations then write different
/// files, of which the loader keeps the most recent. The store is monotonic without a lock.
/// </para>
/// </summary>
sealed partial class RemoteKeys : IRemoteKeys
{
    internal const string TrustFilePattern = "Identity.*.trust";
    internal const string LegacyPublicFilePattern = "Identity.*.public";
    const string DuplicityFolderName = "Duplicity";
    const int MaxDuplicityEvidenceFiles = 16;

    readonly LocalKeys _localKeys;
    readonly IRemoteParty _remote;
    // Guards _pinned, _identity AND the .trust files that mirror them: they must change together, and
    // back tasks and an operator approving a PeeringIssue get here from different threads.
    readonly object _trustLock;
    KeyEvent? _pinned;
    RemoteIdentityKey? _identity;
    readonly TimeSpan _maxClockOffset;
    readonly AutoTrustKey _autoTrustKey;

    // The replay cache belongs here, with the remote it protects: one cache, one lock, one file per
    // remote. Holding it on LocalKeys behind an index keyed by remote name would be a hand-rolled
    // version of the association this object already is.
    readonly RemoteNonceCache _nonceCache;

    RemoteKeys( LocalKeys localKeys,
                IRemoteParty remote,
                KeyEvent? pinned,
                AutoTrustKey autoTrustKey,
                TimeSpan maxClockOffset,
                RemoteNonceCache nonceCache )
    {
        _trustLock = new object();
        _localKeys = localKeys;
        _remote = remote;
        _pinned = pinned;
        _identity = pinned != null ? CreateKey( pinned ) : null;
        _autoTrustKey = autoTrustKey;
        _maxClockOffset = maxClockOffset;
        _nonceCache = nonceCache;
        remote.ApplicationIdentityService.Heartbeat.Sync += OnHeartbeat;
    }

    static RemoteIdentityKey CreateKey( KeyEvent e ) => new RemoteIdentityKey( new RemoteIdentityKeyData( e ) );

    void OnHeartbeat( IActivityMonitor monitor, int callCount )
    {
        // Prune first: an idle process must not hold nonces that can no longer be replayed.
        _nonceCache.Prune( _remote.ApplicationIdentityService.SystemClock.UtcNow, _maxClockOffset );
        _nonceCache.Save( monitor );
    }

    /// <summary>
    /// Called when this remote's keys are unplugged.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="destroyed">
    /// True when the remote party itself is gone, as opposed to the application shutting down. Its
    /// replay record then has no meaning any more, and leaving it behind would resurrect on a party
    /// that later takes the same name.
    /// </param>
    internal void OnTeardown( IActivityMonitor monitor, bool destroyed )
    {
        _remote.ApplicationIdentityService.Heartbeat.Sync -= OnHeartbeat;
        lock( _trustLock ) _identity?.OnTeardown();
        if( destroyed ) _nonceCache.Delete( monitor );
        else _nonceCache.Save( monitor );
    }

    public ILocalKeys LocalKeys => _localKeys;

    public IRemoteParty Party => _remote;

    public RemoteIdentityKey? TrustedIdentity => _identity;

    public KeyEvent? TrustedEvent => _pinned;

    public bool IsTerminated => _pinned?.IsAbandonment == true;

    public AutoTrustKey AutoTrustKey => _autoTrustKey;

    public TimeSpan MaxClockOffset => _maxClockOffset;

    public bool SetTrustedIdentity( IActivityLineEmitter logger, KeyEvent? trusted )
    {
        // An operator pins what a peer presented (a PeeringIssue approval) or a file it was handed. Its
        // signature is the one thing that can be checked without the chain behind it.
        Throw.CheckArgument( "The event must be signed by the key it reveals, for this remote.",
                             trusted == null || trusted.VerifySignature( _remote.FullName ) );
        lock( _trustLock )
        {
            return DoPin( logger, trusted );
        }
    }

    public KeyChainCheck ApplyTail( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail )
    {
        Throw.CheckNotNullArgument( tail );
        // Decided and applied under one lock: two connections rotating the same remote at once must
        // not each see the old pin and each write their own file (M15).
        lock( _trustLock )
        {
            var check = KeyEventChain.Verify( _remote.FullName, tail, _pinned );
            switch( check.Verdict )
            {
                case KeyChainVerdict.Advanced:
                    logger.Info( $"Remote '{_remote}' rotated its identity key: #{_pinned!.Seq} -> #{check.Head!.Seq}." );
                    DoPin( logger, check.Head );
                    break;
                case KeyChainVerdict.Recovered:
                    logger.Warn( $"Remote '{_remote}' recovered its identity with its recovery key, superseding pinned #{_pinned!.Seq}: now #{check.Head!.Seq}." );
                    DoPin( logger, check.Head );
                    break;
                case KeyChainVerdict.Abandoned:
                    // Unknown parties are not pinned, not even to record their end.
                    if( _pinned != null )
                    {
                        logger.Warn( $"Remote '{_remote}' has decommissioned its identity (event #{check.Head!.Seq}): nothing it sends is accepted any more." );
                        DoPin( logger, check.Head );
                    }
                    break;
                case KeyChainVerdict.Terminated:
                    logger.Info( $"Remote '{_remote}' has decommissioned its identity: refused." );
                    break;
                case KeyChainVerdict.Rollback:
                    // Usually a message a rotation overtook. Possibly a superseded key.
                    logger.Warn( $"Remote '{_remote}' presented an identity older than the pinned #{_pinned!.Seq}: refused." );
                    break;
                case KeyChainVerdict.Duplicity:
                    OnDuplicity( logger, check.Held!, check.Conflicting! );
                    break;
            }
            return check;
        }
    }

    public bool AdoptSelfAsserted( IActivityLineEmitter logger, KeyEvent head )
    {
        Throw.CheckNotNullArgument( head );
        lock( _trustLock )
        {
            // Re-read under the lock: another connection may have pinned something meanwhile.
            if( _pinned == null )
            {
                if( _autoTrustKey == AutoTrustKey.Never ) return false;
                logger.Warn( $"Pinning the identity presented by remote '{_remote}' because its '{nameof( AutoTrustKey )}' is {_autoTrustKey}." );
                return DoPin( logger, head );
            }
            return false;
        }
    }

    // Must be called with _trustLock held.
    //
    // The replaced key is deliberately NOT disposed here. A concurrent handshake may be inside
    // RemoteIdentityKey.VerifyHash on that very instance — it took its reference before this
    // rotation — and disposing under it turns a legitimate connection into a spurious authentication
    // failure. The ECDsa wraps a SafeHandle, so not disposing costs one finalizable object per
    // rotation and nothing more. The current key IS disposed, at OnTeardown.
    bool DoPin( IActivityLineEmitter logger, KeyEvent? e )
    {
        Throw.DebugAssert( System.Threading.Monitor.IsEntered( _trustLock ) );
        var current = _pinned;
        if( current == null && e == null ) return false;
        if( current != null && e != null && current.Seq == e.Seq
            && current.GetDigest( _remote.FullName ).Span.SequenceEqual( e.GetDigest( _remote.FullName ).Span ) )
        {
            return false;
        }
        var store = _remote.SharedFileStore;
        if( e != null )
        {
            // Atomic: a crash can't leave a truncated trust anchor that the next start would reject.
            store.WriteAllBytes( GetTrustPath( e.Seq ), e.Encoded );
            if( current == null ) logger.Info( $"Pinning identity #{e.Seq} of remote '{_remote}'." );
        }
        else
        {
            logger.Info( $"Removing the pinned identity of remote '{_remote}'. This remote has no more trusted identity." );
        }
        // Same sequence, other content: the file was just rewritten, there is nothing to trash.
        if( current != null && (e == null || current.Seq != e.Seq) )
        {
            store.TryTrash( logger, GetTrustPath( current.Seq ) );
        }
        _pinned = e;
        _identity = e != null ? CreateKey( e ) : null;
        return true;
    }

    NormalizedPath GetTrustPath( int seq )
        => _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{seq.ToString( CultureInfo.InvariantCulture )}.trust" );

    // Must be called with _trustLock held.
    void OnDuplicity( IActivityLineEmitter logger, KeyEvent held, KeyEvent conflicting )
    {
        var fullName = _remote.FullName;
        var observed = conflicting.GetDigest( fullName );
        try
        {
            var store = _remote.SharedFileStore;
            var folder = store.FolderPath.AppendPart( DuplicityFolderName );
            int existing = Directory.Exists( folder ) ? Directory.EnumerateFiles( folder ).Count() : 0;
            // Bounded: producing a fork takes the committed key, but whoever has it must not be able
            // to fill a disk with evidence of it.
            if( existing + 2 <= MaxDuplicityEvidenceFiles )
            {
                store.CreateDirectory( folder );
                foreach( var e in new[] { held, conflicting } )
                {
                    var name = $"{e.Seq.ToString( CultureInfo.InvariantCulture )}.{Convert.ToHexString( e.GetDigest( fullName ).Span[..6] ).ToLowerInvariant()}.event";
                    var path = folder.AppendPart( name );
                    if( !File.Exists( path ) ) store.WriteAllBytes( path, e.Encoded );
                }
            }
        }
        catch( Exception ex )
        {
            logger.Log( LogLevel.Error, IdentityAlert.LogTag, $"Unable to store the duplicity evidence of remote '{_remote}'.", ex );
        }
        _localKeys.AlertBook.Raise( logger, IdentityAlertKind.RemoteDuplicity, fullName, false, null, held.Seq,
                                    held.GetDigest( fullName ).Span, observed.Span );
    }

    public bool CheckClockOffset( IActivityLineEmitter logger, TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error )
    {
        if( clockOffset > _maxClockOffset || clockOffset < -_maxClockOffset )
        {
            if( logLevel != LogLevel.None ) logger.Log( logLevel, $"Invalid nonce creation time '{clockOffset}' for '{_remote}'. It must be less than '{_maxClockOffset}'." );
            return false;
        }
        return true;
    }

    public bool CheckAndAddNonceValue( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error )
    {
        // Partitioned by remote and checked-and-added in one operation: two concurrent connections
        // replaying the same nonce must not both pass.
        bool ok = _nonceCache.CheckAndAdd( nonce.Nonce,
                                           nonce.CreationTime,
                                           _remote.ApplicationIdentityService.SystemClock.UtcNow,
                                           _maxClockOffset,
                                           out bool evicted,
                                           out var journalError );
        if( journalError != null )
        {
            // Accepted all the same: refusing every handshake on a full or failing disk would be
            // worse than the risk, which is a replay after a crash before the next rewrite.
            logger.Log( LogLevel.Warn, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Unable to journal a nonce of '{_remote}': a crash before the next save of its nonce cache " +
                        $"would forget it. {journalError.Message}" );
        }
        if( evicted )
        {
            // Only a peer handshaking far faster than any legitimate one reaches this, and the
            // degradation is confined to that peer. Worth saying out loud: its replay window is
            // now shorter than configured.
            logger.Log( LogLevel.Warn, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Nonce cache for '{_remote}' is full ({IRemoteKeys.MaxNonceCacheEntries} entries within " +
                        $"{_maxClockOffset}): dropping still-valid entries. This remote is handshaking abnormally fast." );
        }
        if( !ok && logLevel != LogLevel.None )
        {
            logger.Log( logLevel, ActivityMonitor.Tags.ToBeInvestigated,
                        $"Nonce value '{nonce.Nonce:X}' has already been used for '{_remote}'." );
        }
        return ok;
    }

    public bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error )
    {
        return nonce.CheckCreationTimeKind( logger, Party.FullName, logLevel )
               && CheckClockOffset( logger, nonce.CreationTime - _remote.ApplicationIdentityService.SystemClock.UtcNow, logLevel )
               && CheckAndAddNonceValue( logger, nonce, logLevel );
    }
}
