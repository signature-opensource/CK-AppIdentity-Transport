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
/// <para>
/// The events the pin has moved past are kept too, in <c>KeyHistory/{Seq}.event</c>: a regular rotation
/// must not end what the remote signed for the application (<see cref="ApplicationSignature"/>), so the
/// keys it replaced still verify what they issued while they were current. They are dropped once
/// nothing they issued can still be valid, and all of them on a recovery, which condemns them.
/// </para>
/// </summary>
sealed partial class RemoteKeys : IRemoteKeys, IAnchoredKeys
{
    internal const string TrustFilePattern = "Identity.*.trust";
    internal const string LegacyPublicFilePattern = "Identity.*.public";
    const string DuplicityFolderName = "Duplicity";
    internal const string HistoryFolderName = "KeyHistory";
    const int MaxDuplicityEvidenceFiles = 16;

    readonly LocalKeys _localKeys;
    readonly IRemoteParty _remote;
    // Guards _pinned, _identity AND the .trust files that mirror them: they must change together, and
    // back tasks and an operator approving a PeeringIssue get here from different threads.
    readonly object _trustLock;
    KeyEvent? _pinned;
    RemoteIdentityKey? _identity;
    // The events the pin moved past: consecutive, linked, ending just before _pinned. Guarded by
    // _trustLock and mirrored in the KeyHistory folder.
    readonly List<KeyEvent> _history;
    readonly TimeSpan _maxClockOffset;
    readonly AutoTrustKey _autoTrustKey;
    // The anchor read from the running status of the remote in the dev store ("#Dev"), once read.
    KeyCheckpoint? _devAnchor;
    KeyChainVerdict? _refusal;
    // The pin has been cleared because its identity is revoked: nothing replaced it yet. Set from the local revocations
    // only, never from what a peer presents.
    bool _pinRevoked;

    // The replay cache belongs here, with the remote it protects: one cache, one lock, one file per
    // remote. Holding it on LocalKeys behind an index keyed by remote name would be a hand-rolled
    // version of the association this object already is.
    readonly RemoteNonceCache _nonceCache;

    RemoteKeys( LocalKeys localKeys,
                IRemoteParty remote,
                KeyEvent? pinned,
                List<KeyEvent> history,
                AutoTrustKey autoTrustKey,
                TimeSpan maxClockOffset,
                RemoteNonceCache nonceCache )
    {
        _trustLock = new object();
        _localKeys = localKeys;
        _remote = remote;
        _pinned = pinned;
        _history = history;
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
        lock( _trustLock ) PruneHistory( monitor );
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

    IParty IPartyKeys.Party => _remote;

    public SignatureVerdict Check( IActivityLineEmitter logger, string purpose, ReadOnlySpan<byte> data, in ApplicationSignature signature )
    {
        KeyEvent[] chain;
        lock( _trustLock ) chain = _pinned == null ? [] : [.. _history, _pinned];
        // Bounded by this party's KeyRotationDays: what it accepts, whatever the remote is configured with.
        return ApplicationSignature.Check( logger, _remote.FullName, chain, purpose, data, signature,
                                            _remote.ApplicationIdentityService.SystemClock.UtcNow, _maxClockOffset, _localKeys.KeyRotationDays );
    }

    public RemoteIdentityKey? TrustedIdentity => _identity;

    public KeyEvent? TrustedEvent => _pinned;

    public bool IsTerminated => _pinned?.IsAbandonment == true;

    public AutoTrustKey AutoTrustKey => _autoTrustKey;

    public bool IsAnchored => _localKeys.IsAnchored( _remote.FullName );

    public KeyChainVerdict? Refusal => _refusal;

    public bool IsRevoked
    {
        get
        {
            var p = _pinned;
            return _pinRevoked || (p != null && _localKeys.IsRevoked( p.GetIdentity( _remote.FullName ).Span ));
        }
    }

    // Called by the local keys when the revocations change: a revoked pin is cleared (the identity is refused forever).
    internal void OnRevocations( IActivityLineEmitter logger )
    {
        lock( _trustLock )
        {
            if( ClearRevokedPin( logger ) ) _refusal = KeyChainVerdict.Revoked;
        }
    }

    // Must be called with _trustLock held. Clears the pin when its own identity is revoked: a local fact, never what a
    // peer presented.
    bool ClearRevokedPin( IActivityLineEmitter logger )
    {
        if( _pinned == null || !_localKeys.IsRevoked( _pinned.GetIdentity( _remote.FullName ).Span ) ) return false;
        logger.Error( ActivityMonitor.Tags.SecurityCritical, $"The identity of remote '{_remote}' is revoked: its pin #{_pinned.Seq} is cleared." );
        DoPin( logger, null );
        ReplaceHistory( logger, [] );
        _pinRevoked = true;
        return true;
    }

    // Whether a tail is a valid piece of a key event log on its own: every event signed by the key it reveals and linked
    // to the previous one. Only such a tail is taken for the log it names: anyone can write any identity in a forged event.
    bool IsValidLog( IReadOnlyList<KeyEvent> tail )
        => KeyEventChain.Verify( _remote.FullName, tail, null ).Verdict is KeyChainVerdict.Unpinned or KeyChainVerdict.Abandoned;

    public int? HeldByRemoteSeq { get; set; }

    public KeyCheckpoint? GetStatedCheckpoint( IActivityLineEmitter logger )
    {
        lock( _trustLock )
        {
            if( IsAnchored && GetAnchor( logger ) is { } anchor ) return anchor;
            return _pinned != null ? KeyCheckpoint.Of( _remote.FullName, _pinned ) : null;
        }
    }

    // The anchor of this remote: configured, or read from its running status in the dev store ("#Dev"). Null when it
    // can't be read yet (the remote has not started) or when it is not anchored.
    KeyCheckpoint? GetAnchor( IActivityLineEmitter logger )
    {
        if( _localKeys.TrustAnchors.TryGetValue( _remote.FullName, out var a ) ) return a;
        if( !_localKeys.IsDevAnchored( _remote.FullName ) ) return null;
        if( _devAnchor != null ) return _devAnchor;
        // The remote writes its running status in its shared folder of the dev store: the folder of this remote party.
        return _devAnchor = DevAnchors.Read( logger, _remote.FullName.Path, _remote.SharedFileStore.FolderPath );
    }

    string IAnchoredKeys.FullName => _remote.FullName.Path;

    KeyEvent? IAnchoredKeys.Head => _pinned;

    KeyChainCheck IAnchoredKeys.ApplyEvents( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> events ) => ApplyTail( logger, events );

    // Must be called with _trustLock held. The events of an anchored remote are verified from its anchor, at each
    // handshake: the pin comes only from there.
    KeyChainCheck ApplyAnchoredTail( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail )
    {
        var anchor = GetAnchor( logger );
        if( anchor == null )
        {
            logger.Warn( $"The trust anchor of '{_remote}' can't be read yet (the remote has not written its running status in the dev store): refused." );
            return RefuseAnchored( new KeyChainCheck( KeyChainVerdict.AnchorUnavailable ) );
        }
        var check = KeyEventChain.VerifyFromAnchor( _remote.FullName, tail, anchor );
        if( check.Verdict is KeyChainVerdict.UpToDate or KeyChainVerdict.Advanced or KeyChainVerdict.Recovered or KeyChainVerdict.Abandoned )
        {
            var head = check.Head!;
            if( _pinned == null )
            {
                logger.Info( $"Remote '{_remote}' is verified from its trust anchor {anchor}: #{head.Seq} pinned." );
                DoPin( logger, head );
            }
            else if( FollowAnchoredPin( logger, tail, anchor, head ) is { } refused )
            {
                return refused;
            }
            _refusal = null;
            return check;
        }
        // A refusal is believed (it is sticky and raises an issue) only when the presented events are a valid log that
        // contradicts the anchor: anyone can send bytes that don't verify.
        if( !IsValidLog( tail ) )
        {
            logger.Warn( $"Remote '{_remote}' presented events that are not a valid key event log: refused." );
            return new KeyChainCheck( KeyChainVerdict.Invalid );
        }
        switch( check.Verdict )
        {
            case KeyChainVerdict.AnchorMismatch:
                logger.Error( ActivityMonitor.Tags.SecurityCritical,
                              $"Remote '{_remote}' presented a key event log that doesn't match its trust anchor {anchor}: refused (an impostor, a party that incepted again, or a stale anchor)." );
                return RefuseAnchored( check );
            case KeyChainVerdict.AnchorTooOld:
                logger.Warn( $"The trust anchor {anchor} of '{_remote}' is older than the events it presented (from #{tail[0].Seq}): refused." );
                return RefuseAnchored( check );
            default:
                logger.Warn( $"Remote '{_remote}' presented events that can't be verified from its trust anchor {anchor} ({check.Verdict}): refused." );
                return RefuseAnchored( check );
        }
    }

    // Must be called with _trustLock held, once the presented events verified from the anchor up to their head. The pin
    // follows the verified head as it follows any remote: a pin of another log (the remote incepted again, its anchor was
    // updated) or before the anchor (the anchor, configured after it, is the authority) is replaced, but a pin at or after
    // the anchor must be extended: a fork or an older head is refused, even when it verifies from the anchor (a key
    // committed after the anchor, current or retired, must not be enough to move the pin). Returns null when the pin
    // followed, the refusal otherwise (not sticky, like for a remote that is not anchored).
    KeyChainCheck? FollowAnchoredPin( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail, KeyCheckpoint anchor, KeyEvent head )
    {
        var pinned = _pinned!;
        int p = pinned.Seq;
        var fullName = _remote.FullName;
        if( !pinned.GetIdentity( fullName ).Span.SequenceEqual( head.GetIdentity( fullName ).Span ) )
        {
            logger.Error( ActivityMonitor.Tags.SecurityCritical,
                          $"The pinned identity #{p} of '{_remote}' contradicts its trust anchor {anchor} (another log): replaced by the verified #{head.Seq}." );
            DoPin( logger, head );
            ReplaceHistory( logger, [] );
            return null;
        }
        if( p < anchor.Seq )
        {
            // The events from the pin to the anchor are not verified by the anchor: the history is kept only when they
            // link to the pin.
            var fromPin = p >= tail[0].Seq ? KeyEventChain.Verify( fullName, TailFrom( tail, p ), pinned ) : default;
            if( fromPin.Verdict is KeyChainVerdict.Advanced or KeyChainVerdict.Recovered or KeyChainVerdict.Abandoned )
            {
                logger.Info( $"Remote '{_remote}' rotated its identity key: #{p} -> #{head.Seq} (verified from its trust anchor)." );
                MoveOn( logger, tail, fromPin );
            }
            else
            {
                logger.Info( $"Remote '{_remote}' is verified from its trust anchor {anchor}: #{head.Seq} pinned (was #{p})." );
                DoPin( logger, head );
                ReplaceHistory( logger, [] );
            }
            return null;
        }
        var check = KeyEventChain.Verify( fullName, tail, pinned );
        switch( check.Verdict )
        {
            case KeyChainVerdict.UpToDate:
                return null;
            case KeyChainVerdict.Advanced or KeyChainVerdict.Recovered or KeyChainVerdict.Abandoned:
                logger.Info( $"Remote '{_remote}' moved its identity: #{p} -> #{check.Head!.Seq} ({check.Verdict}, verified from its trust anchor)." );
                MoveOn( logger, tail, check );
                return null;
            case KeyChainVerdict.Duplicity:
                OnDuplicity( logger, check.Held!, check.Conflicting! );
                return check;
            case KeyChainVerdict.Rollback:
                logger.Warn( $"Remote '{_remote}' presented an identity older than the pinned #{p}: refused." );
                return check;
            default:
                logger.Warn( ActivityMonitor.Tags.SecurityCritical,
                             $"Remote '{_remote}' presented events that verify from its trust anchor {anchor} but don't extend its pinned #{p} ({check.Verdict}): refused." );
                return check;
        }
    }

    KeyChainCheck RefuseAnchored( KeyChainCheck check )
    {
        _refusal = check.Verdict;
        return check;
    }

    // The events of a tail from the predecessor-linkable point of a pinned sequence on: at most MaxEventTail, for Verify.
    static IReadOnlyList<KeyEvent> TailFrom( IReadOnlyList<KeyEvent> tail, int seq )
    {
        int a = tail[0].Seq;
        int from = Math.Max( seq - a, tail.Count - KeyEventChain.MaxEventWindow );
        var r = new List<KeyEvent>( tail.Count - from );
        for( int i = from; i < tail.Count; ++i ) r.Add( tail[i] );
        return r;
    }

    public TimeSpan MaxClockOffset => _maxClockOffset;

    public bool SetTrustedIdentity( IActivityLineEmitter logger, KeyEvent? trusted )
    {
        if( IsAnchored )
        {
            logger.Warn( $"Remote '{_remote}' is anchored: its identity is verified from its trust anchor, never set by an operator. Update its anchor instead." );
            return false;
        }
        // An operator pins what a peer presented (a PeeringIssue approval) or a file it was handed. Its
        // signature is the one thing that can be checked without the chain behind it.
        Throw.CheckArgument( "The event must be signed by the key it reveals, for this remote.",
                             trusted == null || trusted.VerifySignature( _remote.FullName ) );
        lock( _trustLock )
        {
            if( trusted != null && _localKeys.IsRevoked( trusted.GetIdentity( _remote.FullName ).Span ) )
            {
                logger.Error( ActivityMonitor.Tags.SecurityCritical, $"The identity proposed for remote '{_remote}' is revoked: it can't be pinned." );
                return false;
            }
            // An operator's pin proves no link to what was pinned before: the history goes.
            if( !DoPin( logger, trusted ) ) return false;
            ReplaceHistory( logger, [] );
            return true;
        }
    }

    public bool PinFromCheckpoint( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail, KeyCheckpoint checkpoint )
    {
        Throw.CheckNotNullArgument( tail );
        Throw.CheckNotNullArgument( checkpoint );
        if( IsAnchored )
        {
            logger.Warn( $"Remote '{_remote}' is anchored: its identity is verified from its trust anchor, never pinned from a checkpoint stated by another party." );
            return false;
        }
        if( tail.Count == 0 ) return false;
        lock( _trustLock )
        {
            if( _localKeys.IsRevoked( tail[^1].GetIdentity( _remote.FullName ).Span ) )
            {
                logger.Error( ActivityMonitor.Tags.SecurityCritical, $"The identity presented by remote '{_remote}' is revoked: it can't be pinned." );
                return false;
            }
            var check = KeyEventChain.VerifyFromAnchor( _remote.FullName, tail, checkpoint );
            if( check.Verdict is not (KeyChainVerdict.UpToDate or KeyChainVerdict.Advanced or KeyChainVerdict.Recovered) )
            {
                logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"The events presented by remote '{_remote}' don't verify from the checkpoint {checkpoint} ({check.Verdict}): not pinned." );
                return false;
            }
            // Like an operator's pin: it proves no link to what was pinned before, the history goes.
            if( DoPin( logger, check.Head! ) ) ReplaceHistory( logger, [] );
            _refusal = null;
            return true;
        }
    }

    public KeyChainCheck ApplyTail( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail )
    {
        Throw.CheckNotNullArgument( tail );
        // Decided and applied under one lock: two connections rotating the same remote at once must
        // not each see the old pin and each write their own file (M15).
        lock( _trustLock )
        {
            // A revoked log is refused whatever it presents (and whatever is pinned). What is presented changes nothing
            // here: the pin is cleared only when its own identity is revoked (OnRevocations does it when the revocations
            // change), and a tail that is not a valid log is only invalid.
            if( tail.Count > 0 && _localKeys.IsRevoked( tail[^1].GetIdentity( _remote.FullName ).Span ) )
            {
                if( !IsValidLog( tail ) )
                {
                    logger.Warn( $"Remote '{_remote}' presented events that are not a valid key event log (they name a revoked identity): refused." );
                    return new KeyChainCheck( KeyChainVerdict.Invalid );
                }
                logger.Error( ActivityMonitor.Tags.SecurityCritical, $"Remote '{_remote}' presented a key event log whose identity is revoked: refused." );
                ClearRevokedPin( logger );
                return RefuseAnchored( new KeyChainCheck( KeyChainVerdict.Revoked ) );
            }
            if( IsAnchored ) return ApplyAnchoredTail( logger, tail );
            if( _refusal == KeyChainVerdict.Revoked ) _refusal = null;
            var check = KeyEventChain.Verify( _remote.FullName, tail, _pinned );
            switch( check.Verdict )
            {
                case KeyChainVerdict.Advanced:
                    logger.Info( $"Remote '{_remote}' rotated its identity key: #{_pinned!.Seq} -> #{check.Head!.Seq}." );
                    MoveOn( logger, tail, check );
                    break;
                case KeyChainVerdict.Recovered:
                    logger.Warn( $"Remote '{_remote}' recovered its identity with its recovery key, superseding pinned #{_pinned!.Seq}: now #{check.Head!.Seq}." );
                    MoveOn( logger, tail, check );
                    break;
                case KeyChainVerdict.Abandoned:
                    // Unknown parties are not pinned, not even to record their end.
                    if( _pinned != null )
                    {
                        logger.Warn( $"Remote '{_remote}' has decommissioned its identity (event #{check.Head!.Seq}): nothing it sends is accepted any more." );
                        MoveOn( logger, tail, check );
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
                // An anchored remote is never trusted on first use: it is verified from its anchor. A revoked log never.
                if( _autoTrustKey == AutoTrustKey.Never || IsAnchored || _localKeys.IsRevoked( head.GetIdentity( _remote.FullName ).Span ) ) return false;
                logger.Warn( $"Pinning the identity presented by remote '{_remote}' because its '{nameof( AutoTrustKey )}' is {_autoTrustKey}." );
                return DoPin( logger, head );
            }
            return false;
        }
    }

    // Must be called with _trustLock held. The pin moves to the verified head of the tail. The events it
    // moved past join the history - unless a recovery is among them (Held is then the superseded pin):
    // the recovery condemns everything before it, so the history restarts at the recovery event.
    void MoveOn( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail, KeyChainCheck check )
    {
        Throw.DebugAssert( System.Threading.Monitor.IsEntered( _trustLock ) );
        var previous = _pinned!;
        var head = check.Head!;
        int a = tail[0].Seq;
        List<KeyEvent> history;
        if( check.Held != null )
        {
            int r = head.Seq;
            while( r >= a && !tail[r - a].IsRecovery ) --r;
            history = [];
            for( int seq = r; seq < head.Seq; ++seq ) history.Add( tail[seq - a] );
        }
        else
        {
            history = [.. _history, previous];
            for( int seq = previous.Seq + 1; seq < head.Seq; ++seq ) history.Add( tail[seq - a] );
        }
        DoPin( logger, head );
        ReplaceHistory( logger, history );
    }

    // Must be called with _trustLock held. Writes what is new, removes what is gone, then prunes.
    void ReplaceHistory( IActivityLineEmitter logger, List<KeyEvent> history )
    {
        Throw.DebugAssert( System.Threading.Monitor.IsEntered( _trustLock ) );
        var store = _remote.SharedFileStore;
        var folder = store.FolderPath.AppendPart( HistoryFolderName );
        try
        {
            foreach( var e in _history )
            {
                if( !history.Contains( e ) ) store.TryTrash( logger, GetHistoryPath( folder, e.Seq ), immediateDelete: true );
            }
            if( history.Count > 0 ) store.CreateDirectory( folder );
            foreach( var e in history )
            {
                if( !_history.Contains( e ) ) store.WriteAllBytes( GetHistoryPath( folder, e.Seq ), e.Encoded );
            }
        }
        catch( Exception ex )
        {
            // In memory it is right: only a restart would forget it, and refuse what it verified.
            logger.Log( LogLevel.Error, $"While saving the key history of remote '{_remote}'.", ex );
        }
        _history.Clear();
        _history.AddRange( history );
        PruneHistory( logger );
    }

    // Must be called with _trustLock held. A replaced key issued nothing still valid once the longest
    // lifetime this party accepts has elapsed since its replacement: it is dropped, with the older ones.
    void PruneHistory( IActivityLineEmitter logger )
    {
        Throw.DebugAssert( System.Threading.Monitor.IsEntered( _trustLock ) );
        var limit = _remote.ApplicationIdentityService.SystemClock.UtcNow
                    - TimeSpan.FromDays( _localKeys.KeyRotationDays ) - ApplicationSignature.TimePrecisionSlack;
        int drop = 0;
        while( drop < _history.Count && ReplacedAt( drop ) < limit ) ++drop;
        if( drop == 0 ) return;
        var folder = _remote.SharedFileStore.FolderPath.AppendPart( HistoryFolderName );
        for( int i = 0; i < drop; ++i ) _remote.SharedFileStore.TryTrash( logger, GetHistoryPath( folder, _history[i].Seq ), immediateDelete: true );
        _history.RemoveRange( 0, drop );

        DateTime ReplacedAt( int i ) => (i + 1 < _history.Count ? _history[i + 1] : _pinned!).TimeName;
    }

    static NormalizedPath GetHistoryPath( NormalizedPath folder, int seq )
        => folder.AppendPart( seq.ToString( CultureInfo.InvariantCulture ) + ".event" );

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
        if( e != null ) _pinRevoked = false;
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
