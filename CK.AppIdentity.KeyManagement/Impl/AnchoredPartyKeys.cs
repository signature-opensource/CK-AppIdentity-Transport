using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// An entry of the key directory of a local party: an anchored party that is not one of its remotes. Its events are
/// verified from its anchor the first time, then from the head held. Kept in memory only: verified again from the
/// anchor after a restart.
/// </summary>
sealed class AnchoredPartyKeys : IAnchoredKeys
{
    readonly LocalKeys _localKeys;
    readonly string _fullName;
    readonly object _lock;
    // From the anchored event (or the last recovery) to the head: what a signature is checked against.
    KeyEvent[] _chain;
    KeyCheckpoint? _devAnchor;

    internal AnchoredPartyKeys( LocalKeys localKeys, string fullName )
    {
        _localKeys = localKeys;
        _fullName = fullName;
        _lock = new object();
        _chain = [];
    }

    public string FullName => _fullName;

    public KeyEvent? Head
    {
        get
        {
            var c = _chain;
            return c.Length > 0 ? c[^1] : null;
        }
    }

    public KeyCheckpoint? GetStatedCheckpoint( IActivityLineEmitter logger )
    {
        lock( _lock )
        {
            return _chain.Length > 0 ? KeyCheckpoint.Of( _fullName, _chain[^1] ) : GetAnchor( logger );
        }
    }

    public SignatureVerdict Check( IActivityLineEmitter logger, string purpose, ReadOnlySpan<byte> data, in ApplicationSignature signature )
    {
        var chain = _chain;
        if( chain.Length > 0 && _localKeys.IsRevoked( chain[^1].GetIdentity( _fullName ).Span ) )
        {
            logger.Warn( ActivityMonitor.Tags.SecurityCritical, $"The identity of '{_fullName}' is revoked: its signature is refused." );
            return SignatureVerdict.Refused;
        }
        return ApplicationSignature.Check( logger, _fullName, chain, purpose, data, signature,
                                           _localKeys.Party.ApplicationIdentityService.SystemClock.UtcNow,
                                           IRemoteKeys.DefaultMaxClockOffset,
                                           _localKeys.KeyRotationDays );
    }

    public KeyChainCheck ApplyEvents( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> events )
    {
        Throw.CheckNotNullArgument( events );
        lock( _lock )
        {
            var anchor = GetAnchor( logger );
            if( anchor == null )
            {
                logger.Warn( $"The trust anchor of '{_fullName}' can't be read yet (the party has not written its running status in the dev store): its events are refused." );
                return new KeyChainCheck( KeyChainVerdict.AnchorUnavailable );
            }
            if( events.Count == 0 ) return new KeyChainCheck( KeyChainVerdict.Invalid );
            // A revoked log is refused whatever it presents (what is held of it is forgotten by OnRevocations).
            if( _localKeys.IsRevoked( events[^1].GetIdentity( _fullName ).Span ) )
            {
                logger.Error( ActivityMonitor.Tags.SecurityCritical, $"The key events received for '{_fullName}' are of a revoked identity: refused." );
                return new KeyChainCheck( KeyChainVerdict.Revoked );
            }
            var held = _chain.Length > 0 ? _chain[^1] : null;
            var check = held == null
                            ? KeyEventChain.VerifyFromAnchor( _fullName, events, anchor )
                            : KeyEventChain.Verify( _fullName, events, held );
            switch( check.Verdict )
            {
                case KeyChainVerdict.UpToDate or KeyChainVerdict.Advanced or KeyChainVerdict.Recovered or KeyChainVerdict.Abandoned:
                    var head = check.Head!;
                    if( held != null && head.Seq == held.Seq ) return check;
                    // The new events: after the anchored event, or after the head held.
                    int from = held == null ? anchor.Seq : held.Seq + 1;
                    var chain = new List<KeyEvent>( held == null ? [] : _chain );
                    int a = events[0].Seq;
                    for( int seq = from; seq <= head.Seq; ++seq ) chain.Add( events[seq - a] );
                    // A recovery condemns everything before it.
                    int r = chain.FindLastIndex( e => e.IsRecovery );
                    if( r > 0 ) chain.RemoveRange( 0, r );
                    Prune( chain );
                    _chain = chain.ToArray();
                    logger.Info( held == null
                                    ? $"The keys of '{_fullName}' are verified from its trust anchor {anchor}: #{head.Seq}."
                                    : $"'{_fullName}' rotated its identity key: #{held.Seq} -> #{head.Seq}." );
                    return check;
                case KeyChainVerdict.AnchorMismatch:
                    logger.Error( ActivityMonitor.Tags.SecurityCritical,
                                  $"The key events received for '{_fullName}' don't match its trust anchor {anchor}: refused (an impostor, a party that incepted again, or a stale anchor)." );
                    return check;
                case KeyChainVerdict.Duplicity:
                    logger.Error( ActivityMonitor.Tags.SecurityCritical,
                                  $"The key events received for '{_fullName}' contradict its verified #{held!.Seq}: two validly signed events at the same position, a committed key leaked. Refused." );
                    return check;
                case KeyChainVerdict.AnchorTooOld:
                    logger.Warn( $"The trust anchor {anchor} of '{_fullName}' is older than its events (from #{events[0].Seq}): it must be updated." );
                    return check;
                default:
                    logger.Warn( $"The key events received for '{_fullName}' can't be verified ({check.Verdict}): refused." );
                    return check;
            }
        }
    }

    // Called by the local keys when the revocations change: what is held of a revoked identity is forgotten (its events
    // are verified from the anchor again, and a revoked log is refused).
    internal void OnRevocations( IActivityLineEmitter logger )
    {
        lock( _lock )
        {
            if( _chain.Length > 0 && _localKeys.IsRevoked( _chain[^1].GetIdentity( _fullName ).Span ) )
            {
                logger.Error( ActivityMonitor.Tags.SecurityCritical, $"The identity of '{_fullName}' is revoked: its keys are forgotten." );
                _chain = [];
            }
        }
    }

    // A replaced key issued nothing still valid once the longest lifetime this party accepts has elapsed since its
    // replacement: it is dropped, with the older ones (the head is kept).
    void Prune( List<KeyEvent> chain )
    {
        var limit = _localKeys.Party.ApplicationIdentityService.SystemClock.UtcNow
                    - TimeSpan.FromDays( _localKeys.KeyRotationDays ) - ApplicationSignature.TimePrecisionSlack;
        int drop = 0;
        while( drop < chain.Count - 1 && chain[drop + 1].TimeName < limit ) ++drop;
        if( drop > 0 ) chain.RemoveRange( 0, drop );
    }

    // The configured anchor, or the one read from the running status in the dev store ("#Dev").
    KeyCheckpoint? GetAnchor( IActivityLineEmitter logger )
    {
        if( _localKeys.TrustAnchors.TryGetValue( _fullName, out var a ) ) return a;
        if( _devAnchor != null || !_localKeys.IsDevAnchored( _fullName ) ) return _devAnchor;
        return _devAnchor = DevAnchors.Read( logger, _fullName, DevAnchors.GetSharedFolder( _localKeys.Party, _fullName ) );
    }
}
