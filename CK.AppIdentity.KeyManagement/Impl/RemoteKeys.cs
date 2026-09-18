using CK.Core;
using System;

namespace CK.AppIdentity.KeyManagement;

sealed partial class RemoteKeys : IRemoteKeys
{
    internal const string PublicIdentityFilePattern = "Identity.*.public";
    readonly LocalKeys _localKeys;
    readonly IRemoteParty _remote;
    // Guards _identity AND the .public files that mirror it: the pair must change together, and both
    // back tasks and an operator approving a PeeringIssue can get here from different threads.
    readonly object _trustLock;
    RemoteIdentityKey? _identity;
    readonly TimeSpan _maxClockOffset;
    readonly AutoTrustKey _autoTrustKey;

    // The replay cache belongs here, with the remote it protects: one cache, one lock, one file per
    // remote. It used to be a single shared ring on LocalKeys indexed by remote name, which was a
    // hand-rolled index onto the association this object already is.
    readonly RemoteNonceCache _nonceCache;

    RemoteKeys( LocalKeys localKeys,
                IRemoteParty remote,
                RemoteIdentityKey? identity,
                AutoTrustKey autoTrustKey,
                TimeSpan maxClockOffset,
                RemoteNonceCache nonceCache )
    {
        _trustLock = new object();
        _localKeys = localKeys;
        _remote = remote;
        _identity = identity;
        _autoTrustKey = autoTrustKey;
        _maxClockOffset = maxClockOffset;
        _nonceCache = nonceCache;
        remote.ApplicationIdentityService.Heartbeat.Sync += OnHeartbeat;
    }

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

    public AutoTrustKey AutoTrustKey => _autoTrustKey;

    public TimeSpan MaxClockOffset => _maxClockOffset;

    public bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKeyData? identity )
    {
        lock( _trustLock )
        {
            if( !SaveDifferingKey( logger, identity ) ) return false;
            _identity = identity != null ? new RemoteIdentityKey( identity ) : null;
            return true;
        }
    }

    public bool SetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity )
    {
        lock( _trustLock )
        {
            if( !SaveDifferingKey( logger, identity ) ) return false;
            _identity = identity;
            return true;
        }
    }

    // Must be called with _trustLock held.
    //
    // The replaced key is deliberately NOT disposed here. A concurrent handshake may be inside
    // RemoteIdentityKey.VerifyHash on that very instance — it took its reference before this
    // rotation — and disposing under it turns a legitimate connection into a spurious authentication
    // failure. The ECDsa wraps a SafeHandle, so not disposing costs one finalizable object per
    // rotation and nothing more; rotations are an AllowedOfflineDays affair, tens of days apart.
    // Trading that for a correctness hazard would be a bad bargain. The current key IS disposed, at
    // OnTeardown, when nothing can be using it any more.
    bool DoSetTrustedIdentity( IActivityLineEmitter logger, RemoteIdentityKey? identity )
    {
        Throw.DebugAssert( System.Threading.Monitor.IsEntered( _trustLock ) );
        if( !SaveDifferingKey( logger, identity ) ) return false;
        _identity = identity;
        return true;
    }

    bool SaveDifferingKey( IActivityLineEmitter logger, IPublicKeyData? identity )
    {
        RemoteIdentityKey? current = _identity;
        if( (current == null && identity == null)
            || (current != null && current.Equals( identity )) )
        {
            return false;
        }
        if( identity != null )
        {
            var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{identity.Name}.public" );
            identity.WritePublicKeyFile( cPath );
            if( current == null )
            {
                logger.Info( $"Saving new trusted identity '{identity.Name}' for remote '{_remote}'." );
            }
        }
        if( current != null )
        {
            if( identity == null )
            {
                logger.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}'. This remote has no more trusted identity." );
            }
            else
            {
                logger.Info( $"Removing trusted identity '{current.Name}' for remote '{_remote}', replaced by '{identity.Name}'." );
            }
            var cPath = _remote.SharedFileStore.FolderPath.AppendPart( $"Identity.{current.Name}.public" );
            _remote.SharedFileStore.TryTrash( logger, cPath );
        }
        return true;
    }

    /// <summary>
    /// The single implementation of "a verified message just told us something about this remote's
    /// keys". <c>RemoteKeysExtensions.OnReadIdentityKeys</c> delegates here.
    /// <para>
    /// It used to exist twice, verbatim, with only the extension being called (L2) — and the decision
    /// was a read of <see cref="TrustedIdentity"/>, then a second read of the same field inside
    /// <c>SaveDifferingKey</c>, then a write, all from back tasks running on their own threads. Two
    /// connections rotating a key at the same time could each see the old key, each write their own
    /// <c>.public</c> file and each trash the old one, leaving a store with two identity files and no
    /// agreement about which is trusted — a mess that outlives the process, since that is what the
    /// next start reads.
    /// </para>
    /// <para>
    /// Deciding and writing under one lock fixes that. What it deliberately does not try to fix is a
    /// stale message landing after a newer one and moving the trusted key back to an earlier one of
    /// the remote's own keys: that message was signed by a key we trust, the key it names is in the
    /// remote's own list, and the remote's next connection presents its current key again and pulls
    /// us forward. It is staleness, not a downgrade an attacker can force, and it heals itself.
    /// </para>
    /// </summary>
    public bool ApplyReadTrustInfo( IActivityLineEmitter logger, in ReadTrustInfo trustInfo )
    {
        Throw.CheckArgument( trustInfo.CurrentKey == null || trustInfo.CurrentKey.Equals( trustInfo.CurrentKeyData ) );
        Throw.CheckArgument( !trustInfo.FoundTrustedKey || TrustedIdentity != null );
        lock( _trustLock )
        {
            // Re-read under the lock: the caller computed FoundTrustedKey against whatever was
            // trusted when it verified the signature, which another connection may have changed.
            var current = _identity;
            if( trustInfo.FoundTrustedKey )
            {
                // We trust the remote (we can update our trusted identity key).
                if( current != null && !current.Equals( trustInfo.CurrentKeyData ) )
                {
                    logger.Info( $"Updating the remote '{Party}' trusted key that has changed." );
                    return DoSetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
                }
            }
            else if( current == null )
            {
                // We have no trusted key. Depending on AutoTrustKey we may adopt the presented one.
                if( AutoTrustKey != AutoTrustKey.Never )
                {
                    logger.Warn( $"Initializing the remote '{Party}' trusted key because its '{nameof( AutoTrustKey )}' is {AutoTrustKey}." );
                    return DoSetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
                }
            }
            else if( AutoTrustKey == AutoTrustKey.Always )
            {
                logger.Warn( $"Updating the remote '{Party}' trusted key because its '{nameof( AutoTrustKey )}' is {AutoTrustKey}." );
                return DoSetTrustedIdentity( logger, trustInfo.CurrentKey ?? new RemoteIdentityKey( trustInfo.CurrentKeyData ) );
            }
            return false;
        }
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
                                           out bool evicted );
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
               && CheckClockOffset( logger, nonce.CreationTime - _remote.ApplicationIdentityService.SystemClock.UtcNow )
               && CheckAndAddNonceValue( logger, nonce, logLevel );
    }
}
