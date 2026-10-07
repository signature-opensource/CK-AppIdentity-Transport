using CK.Core;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Outcome of <see cref="KeyEventChain.Verify"/>.
/// </summary>
public enum KeyChainVerdict
{
    /// <summary>
    /// The tail is malformed, a link is broken or a signature is wrong. Nothing in it can be used.
    /// </summary>
    Invalid,

    /// <summary>
    /// Nothing was pinned. The tail is consistent, but its <see cref="KeyChainCheck.Head"/> is only
    /// what the sender asserts: adopting it is a trust-on-first-use decision.
    /// </summary>
    Unpinned,

    /// <summary>
    /// The head of the tail is the pinned event.
    /// </summary>
    UpToDate,

    /// <summary>
    /// The tail extends the pinned event through valid rotations: the pin moves to <see cref="KeyChainCheck.Head"/>.
    /// </summary>
    Advanced,

    /// <summary>
    /// The tail holds a recovery event revealing the recovery key the pinned event commits to: it
    /// supersedes the pin, whatever ordinary events led to it, and the pin moves to <see cref="KeyChainCheck.Head"/>.
    /// <see cref="KeyChainCheck.Held"/> is the superseded pin.
    /// </summary>
    Recovered,

    /// <summary>
    /// The verified head is an abandonment: the identity has ended, and the pin becomes terminal.
    /// </summary>
    Abandoned,

    /// <summary>
    /// The pinned event is an abandonment: this identity has ended and nothing it sends is accepted.
    /// </summary>
    Terminated,

    /// <summary>
    /// The tail starts too far after the pinned event to link to it.
    /// </summary>
    TooFarBehind,

    /// <summary>
    /// The tail ends before the pinned event. Usually a message overtaken by a rotation; possibly
    /// the holder of a superseded key.
    /// </summary>
    Rollback,

    /// <summary>
    /// The tail holds a validly signed event at the pinned sequence that differs from the pinned one.
    /// Only the holder of that sequence's committed key can produce it: this is proof that the key
    /// leaked. <see cref="KeyChainCheck.Held"/> and <see cref="KeyChainCheck.Conflicting"/> are the evidence.
    /// </summary>
    Duplicity
}

/// <summary>
/// Result of <see cref="KeyEventChain.Verify"/>.
/// </summary>
/// <param name="Verdict">The verdict.</param>
/// <param name="Head">
/// The verified head of the tail for <see cref="KeyChainVerdict.Unpinned"/>, <see cref="KeyChainVerdict.UpToDate"/>,
/// <see cref="KeyChainVerdict.Advanced"/> and <see cref="KeyChainVerdict.Abandoned"/>. Null otherwise.
/// </param>
/// <param name="Held">The pinned event, for <see cref="KeyChainVerdict.Duplicity"/>.</param>
/// <param name="Conflicting">The event that conflicts with it, for <see cref="KeyChainVerdict.Duplicity"/>.</param>
public readonly record struct KeyChainCheck( KeyChainVerdict Verdict, KeyEvent? Head = null, KeyEvent? Held = null, KeyEvent? Conflicting = null );

/// <summary>
/// Verifies a tail of key events against what a verifier has pinned for a party.
/// <para>
/// This is pure: no I/O, no state. It decides; the caller applies the decision under its own lock.
/// </para>
/// </summary>
public static class KeyEventChain
{
    /// <summary>
    /// The maximal number of events a party sends. A verifier more than this many rotations behind
    /// cannot catch up from a handshake and needs an operator to re-pin.
    /// </summary>
    public const int MaxEventTail = 8;

    /// <summary>
    /// Verifies a tail of events sent by <paramref name="fullName"/> against the <paramref name="pinned"/> event.
    /// </summary>
    /// <param name="fullName">The full name of the party whose log this is.</param>
    /// <param name="tail">The events, consecutive, oldest first. The last one is the sender's head.</param>
    /// <param name="pinned">The event pinned for this party, null if none.</param>
    /// <returns>The verdict.</returns>
    public static KeyChainCheck Verify( string fullName, IReadOnlyList<KeyEvent> tail, KeyEvent? pinned )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckNotNullArgument( tail );
        if( tail.Count == 0 || tail.Count > MaxEventTail ) return new KeyChainCheck( KeyChainVerdict.Invalid );
        int a = tail[0].Seq;
        for( int i = 1; i < tail.Count; ++i )
        {
            if( tail[i].Seq != a + i ) return new KeyChainCheck( KeyChainVerdict.Invalid );
        }
        var head = tail[^1];
        int m = head.Seq;

        if( pinned == null )
        {
            // Nothing to link to: the tail can only be checked against itself.
            if( !tail[0].VerifySignature( fullName ) ) return new KeyChainCheck( KeyChainVerdict.Invalid );
            for( int i = 1; i < tail.Count; ++i )
            {
                if( !Links( fullName, tail[i - 1], tail[i] ) ) return new KeyChainCheck( KeyChainVerdict.Invalid );
            }
            return new KeyChainCheck( head.IsAbandonment ? KeyChainVerdict.Abandoned : KeyChainVerdict.Unpinned, head );
        }

        // A recovery event that reveals the recovery key the pin commits to supersedes the pin, whatever
        // it is: a chain someone moved with a stolen next key, the event a fork was built on, even an
        // abandonment. Ordinary events carry the recovery commitment unchanged, so whoever moved the pin
        // without the recovery key left it in place - and only its holder can produce this event. It is
        // checked before anything else, sequence order included: superseding is the point.
        if( pinned.HasRecovery )
        {
            for( int j = tail.Count - 1; j >= 0; --j )
            {
                var r = tail[j];
                if( !r.IsRecovery || !pinned.CommitsToRecovery( r.Spki.Span ) ) continue;
                if( !r.VerifySignature( fullName ) ) return new KeyChainCheck( KeyChainVerdict.Invalid );
                for( int i = j + 1; i < tail.Count; ++i )
                {
                    if( !Links( fullName, tail[i - 1], tail[i] ) ) return new KeyChainCheck( KeyChainVerdict.Invalid );
                }
                return new KeyChainCheck( head.IsAbandonment ? KeyChainVerdict.Abandoned : KeyChainVerdict.Recovered, head, Held: pinned );
            }
        }

        if( pinned.IsAbandonment ) return new KeyChainCheck( KeyChainVerdict.Terminated );
        int s = pinned.Seq;
        if( m < s ) return new KeyChainCheck( KeyChainVerdict.Rollback );
        // When s == a - 1 the pinned event is the tail's predecessor: still linkable.
        if( s < a - 1 ) return new KeyChainCheck( KeyChainVerdict.TooFarBehind );

        if( s >= a )
        {
            var presented = tail[s - a];
            if( !SameDigest( presented.GetDigest( fullName ).Span, pinned.GetDigest( fullName ).Span ) )
            {
                // A different event at the pinned sequence is proof of a leaked key only if it is
                // validly signed by the very key the pinned event reveals (the one that was committed
                // to). Anything else is merely invalid: a forged "fork" must not raise an alarm.
                if( presented.Spki.Span.SequenceEqual( pinned.Spki.Span ) && presented.VerifySignature( fullName ) )
                {
                    return new KeyChainCheck( KeyChainVerdict.Duplicity, Held: pinned, Conflicting: presented );
                }
                return new KeyChainCheck( KeyChainVerdict.Invalid );
            }
            if( s == m ) return new KeyChainCheck( KeyChainVerdict.UpToDate, head );
        }

        // Walk from the pinned event to the head. Events before the pinned one are not examined:
        // they are already behind us and we hold nothing to compare them with.
        var previous = pinned;
        for( int seq = s + 1; seq <= m; ++seq )
        {
            var e = tail[seq - a];
            if( !Links( fullName, previous, e ) ) return new KeyChainCheck( KeyChainVerdict.Invalid );
            previous = e;
        }
        return new KeyChainCheck( head.IsAbandonment ? KeyChainVerdict.Abandoned : KeyChainVerdict.Advanced, head );
    }

    /// <summary>
    /// Checks a whole log, from its inception: what a party verifies of its own log when it loads it.
    /// Unlike <see cref="Verify"/>, the length is not bounded.
    /// </summary>
    /// <param name="fullName">The full name of the party whose log this is.</param>
    /// <param name="log">The events, from the inception.</param>
    /// <returns>True if the log starts at an inception, is signed and linked throughout, and ends no later than its first abandonment.</returns>
    public static bool IsValidLog( string fullName, IReadOnlyList<KeyEvent> log )
    {
        Throw.CheckNotNullOrEmptyArgument( fullName );
        Throw.CheckNotNullArgument( log );
        if( log.Count == 0 || !log[0].IsInception || !log[0].VerifySignature( fullName ) ) return false;
        for( int i = 1; i < log.Count; ++i )
        {
            if( !Links( fullName, log[i - 1], log[i] ) ) return false;
        }
        return true;
    }

    /// <summary>
    /// <paramref name="next"/> follows <paramref name="previous"/>: it names previous as its predecessor,
    /// is signed by the key it reveals, and that key is either the next key previous committed to (an
    /// ordinary event, which must then carry the recovery commitment unchanged) or the recovery key
    /// previous committed to (a recovery event, which may commit to a new one).
    /// </summary>
    internal static bool Links( string fullName, KeyEvent previous, KeyEvent next )
    {
        return next.Seq == previous.Seq + 1
               && (next.IsRecovery
                    ? previous.CommitsToRecovery( next.Spki.Span )
                    : previous.CommitsTo( next.Spki.Span ) && SameDigest( next.RecoveryCommit.Span, previous.RecoveryCommit.Span ))
               && SameDigest( next.PrevDigest.Span, previous.GetDigest( fullName ).Span )
               && next.VerifySignature( fullName );
    }

    static bool SameDigest( ReadOnlySpan<byte> x, ReadOnlySpan<byte> y ) => CryptographicOperations.FixedTimeEquals( x, y );
}
