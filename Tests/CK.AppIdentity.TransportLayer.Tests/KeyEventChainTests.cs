using CK.AppIdentity.KeyManagement;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The key event log, as pure code: encoding, signatures, and the verdicts of
/// <see cref="KeyEventChain.Verify"/> (DESIGN-key-pre-rotation §3 and §7).
/// </summary>
[TestFixture]
public class KeyEventChainTests
{
    const string Party = "Test/$KelParty";

    /// <summary>
    /// A party's log with all its keys: key i is revealed by event i, and event i commits to key i+1.
    /// </summary>
    sealed class Log : IDisposable
    {
        public readonly List<ECDsa> Keys = new();
        public readonly List<KeyEvent> Events = new();

        public Log( int eventCount, string fullName = Party, bool abandonAtEnd = false )
        {
            for( int i = 0; i <= eventCount; ++i ) Keys.Add( NewKey() );
            var t = DateTime.UtcNow.AddDays( -eventCount );
            for( int i = 0; i < eventCount; ++i )
            {
                bool last = i == eventCount - 1;
                var commit = last && abandonAtEnd ? ReadOnlySpan<byte>.Empty : Commit( Keys[i + 1] );
                Events.Add( KeyEvent.Create( fullName, i, t.AddDays( i ), Keys[i], commit, i == 0 ? null : Events[i - 1] ) );
            }
        }

        public IReadOnlyList<KeyEvent> Tail( int from, int toInclusive ) => Events.Skip( from ).Take( toInclusive - from + 1 ).ToList();

        public void Dispose()
        {
            foreach( var k in Keys ) k.Dispose();
        }
    }

    static ECDsa NewKey()
    {
        var k = ECDsa.Create();
        k.KeySize = 256;
        return k;
    }

    static byte[] Commit( ECDsa k ) => KeyEvent.ComputeCommit( k.ExportSubjectPublicKeyInfo() );

    // --- Encoding --------------------------------------------------------------------------------

    [Test]
    public void an_event_round_trips_through_its_encoding()
    {
        using var log = new Log( 3 );
        foreach( var e in log.Events )
        {
            var back = KeyEvent.Read( e.Encoded.Span );
            back.Encoded.ToArray().ShouldBe( e.Encoded.ToArray() );
            back.GetDigest( Party ).ToArray().ShouldBe( e.GetDigest( Party ).ToArray() );
            back.VerifySignature( Party ).ShouldBeTrue();
            back.Seq.ShouldBe( e.Seq );
            back.TimeName.ShouldBe( e.TimeName );
        }
    }

    [Test]
    public void reading_refuses_truncated_trailing_and_oversized_data()
    {
        using var log = new Log( 2 );
        var bytes = log.Events[1].Encoded.ToArray();
        Should.Throw<InvalidDataException>( () => KeyEvent.Read( bytes.AsSpan( 0, bytes.Length - 1 ) ) );
        Should.Throw<InvalidDataException>( () => KeyEvent.Read( bytes.Concat( new byte[] { 0 } ).ToArray() ) );

        // A public key length beyond the bound a peer may make us allocate.
        var oversized = (byte[])bytes.Clone();
        oversized[12] = 0xFF;
        oversized[13] = 0xFF;
        Should.Throw<InvalidDataException>( () => KeyEvent.Read( oversized ) );
    }

    [Test]
    public void only_the_inception_may_have_no_previous_event()
    {
        using var log = new Log( 2 );
        // Zero the PrevDigest of event 1: it would claim to have no predecessor.
        var bytes = log.Events[1].Encoded.ToArray();
        int prevOffset = 4 + 8 + 2 + log.Events[1].Spki.Length + KeyEvent.HashSize;
        Array.Clear( bytes, prevOffset, KeyEvent.HashSize );
        Should.Throw<InvalidDataException>( () => KeyEvent.Read( bytes ) );
    }

    [Test]
    public void the_digest_does_not_cover_the_malleable_signature()
    {
        // ECDSA: if (r, s) is valid then so is (r, n - s). Whoever relays an event can produce that
        // second form. If the digest covered the signature, a relay could change an event's identity
        // without changing the event, and an honest log would look like a fork.
        using var log = new Log( 1 );
        var e = log.Events[0];
        var bytes = e.Encoded.ToArray();
        int sigOffset = bytes.Length - 64;
        var n = BigInteger.Parse( "0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", System.Globalization.NumberStyles.HexNumber );
        var s = new BigInteger( bytes.AsSpan( sigOffset + 32, 32 ), isUnsigned: true, isBigEndian: true );
        var flipped = (n - s).ToByteArray( isUnsigned: true, isBigEndian: true );
        Array.Clear( bytes, sigOffset + 32, 32 );
        flipped.CopyTo( bytes, sigOffset + 64 - flipped.Length );

        var twin = KeyEvent.Read( bytes );
        twin.Signature.ToArray().ShouldNotBe( e.Signature.ToArray(), "The test must actually produce a different signature." );
        twin.VerifySignature( Party ).ShouldBeTrue( "Both forms are valid: that is the malleability." );
        twin.GetDigest( Party ).ToArray().ShouldBe( e.GetDigest( Party ).ToArray() );
        KeyEventChain.Verify( Party, new[] { twin }, e ).Verdict.ShouldBe( KeyChainVerdict.UpToDate );
    }

    [Test]
    public void an_event_of_one_party_does_not_verify_as_another_party_s()
    {
        using var log = new Log( 2 );
        log.Events[0].VerifySignature( Party ).ShouldBeTrue();
        log.Events[0].VerifySignature( "Test/$SomeoneElse" ).ShouldBeFalse();
        KeyEventChain.Verify( "Test/$SomeoneElse", log.Tail( 0, 1 ), null ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
    }

    // --- Verdicts --------------------------------------------------------------------------------

    [Test]
    public void an_unpinned_party_is_only_self_asserted()
    {
        using var log = new Log( 3 );
        var c = KeyEventChain.Verify( Party, log.Tail( 0, 2 ), null );
        c.Verdict.ShouldBe( KeyChainVerdict.Unpinned );
        c.Head.ShouldBeSameAs( log.Events[2] );
    }

    [Test]
    public void the_pinned_head_is_up_to_date()
    {
        using var log = new Log( 3 );
        var c = KeyEventChain.Verify( Party, log.Tail( 0, 2 ), log.Events[2] );
        c.Verdict.ShouldBe( KeyChainVerdict.UpToDate );
    }

    [Test]
    public void a_legitimate_rotation_advances_the_pin()
    {
        using var log = new Log( 2 );
        var c = KeyEventChain.Verify( Party, log.Tail( 0, 1 ), log.Events[0] );
        c.Verdict.ShouldBe( KeyChainVerdict.Advanced );
        c.Head.ShouldBeSameAs( log.Events[1] );
        // The tail may also start right after the pin: the pin is then the predecessor.
        KeyEventChain.Verify( Party, log.Tail( 1, 1 ), log.Events[0] ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
    }

    [Test]
    public void a_verifier_seven_rotations_behind_catches_up_and_eight_behind_cannot()
    {
        using var log = new Log( 10 );
        // Head is event 9, the tail carries 2..9 (8 events).
        var tail = log.Tail( 2, 9 );
        tail.Count.ShouldBe( KeyEventChain.MaxEventTail );
        var c = KeyEventChain.Verify( Party, tail, log.Events[1] );
        c.Verdict.ShouldBe( KeyChainVerdict.Advanced, "Pinned at 1, the tail starts at 2: linkable." );
        c.Head.ShouldBeSameAs( log.Events[9] );
        KeyEventChain.Verify( Party, tail, log.Events[0] ).Verdict.ShouldBe( KeyChainVerdict.TooFarBehind );
    }

    [Test]
    public void a_tail_that_ends_before_the_pin_is_a_rollback()
    {
        using var log = new Log( 3 );
        KeyEventChain.Verify( Party, log.Tail( 0, 1 ), log.Events[2] ).Verdict.ShouldBe( KeyChainVerdict.Rollback );
    }

    [Test]
    public void malformed_tails_are_invalid()
    {
        using var log = new Log( 10 );
        KeyEventChain.Verify( Party, Array.Empty<KeyEvent>(), null ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
        KeyEventChain.Verify( Party, log.Tail( 0, 8 ), null ).Verdict.ShouldBe( KeyChainVerdict.Invalid, "9 events: beyond MaxEventTail." );
        KeyEventChain.Verify( Party, new[] { log.Events[0], log.Events[2] }, null ).Verdict.ShouldBe( KeyChainVerdict.Invalid, "A gap." );
        KeyEventChain.Verify( Party, new[] { log.Events[1], log.Events[0] }, null ).Verdict.ShouldBe( KeyChainVerdict.Invalid, "Out of order." );
    }

    // --- The thief: holds the CURRENT key, never the committed next one --------------------------

    [Test]
    public void a_thief_holding_the_current_key_cannot_advance_the_pin()
    {
        // The unit form of the takeover test: the thief holds key 1 (the current key, revealed by the
        // pinned event 1) and wants the verifier to move to a key of its own.
        using var log = new Log( 2 );
        var pinned = log.Events[1];
        using var thiefKey = NewKey();
        var now = DateTime.UtcNow;

        // 1. Its own key, signing for itself. The commitment of event 1 is to key 2, not to this.
        var selfSigned = Forge( seq: 2, now, revealed: thiefKey, signer: thiefKey, nextCommit: Commit( thiefKey ), previous: pinned );
        KeyEventChain.Verify( Party, new[] { selfSigned }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // 2. Its own key, vouched for by the stolen current key: exactly what today's protocol accepts.
        var vouched = Forge( seq: 2, now, revealed: thiefKey, signer: log.Keys[1], nextCommit: Commit( thiefKey ), previous: pinned );
        KeyEventChain.Verify( Party, new[] { vouched }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // 3. Re-revealing the stolen key at the next sequence, committing onward to its own key.
        var replayed = Forge( seq: 2, now, revealed: log.Keys[1], signer: log.Keys[1], nextCommit: Commit( thiefKey ), previous: pinned );
        KeyEventChain.Verify( Party, new[] { replayed }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // Meanwhile the legitimate rotation goes through.
        KeyEventChain.Verify( Party, new[] { log.Events[1] }, log.Events[0] ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
    }

    [Test]
    public void a_thief_holding_only_the_current_key_cannot_abandon_the_identity()
    {
        using var log = new Log( 2 );
        var pinned = log.Events[1];
        // An abandonment at 2 must reveal key 2. Revealing key 1 instead fails the commitment.
        var abandon = Forge( seq: 2, DateTime.UtcNow, revealed: log.Keys[1], signer: log.Keys[1], nextCommit: new byte[KeyEvent.HashSize], previous: pinned );
        abandon.IsAbandonment.ShouldBeTrue();
        KeyEventChain.Verify( Party, new[] { abandon }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
    }

    [Test]
    public void each_broken_link_is_invalid_on_its_own()
    {
        using var log = new Log( 3 );
        var pinned = log.Events[0];
        var good = log.Events[1];
        var now = good.TimeName;

        // Commitment: the right predecessor and a valid self-signature, but not the committed key.
        using var other = NewKey();
        var wrongKey = Forge( 1, now, other, other, Commit( log.Keys[2] ), pinned );
        KeyEventChain.Verify( Party, new[] { wrongKey }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // PrevDigest: the committed key, validly signed, but naming another predecessor.
        var wrongPrev = Forge( 1, now, log.Keys[1], log.Keys[1], Commit( log.Keys[2] ), pinned, prevDigest: RandomNumberGenerator.GetBytes( 32 ) );
        KeyEventChain.Verify( Party, new[] { wrongPrev }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // Signature: everything right but the signature.
        var bytes = good.Encoded.ToArray();
        bytes[^1] ^= 0x01;
        KeyEventChain.Verify( Party, new[] { KeyEvent.Read( bytes ) }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        // And unchanged, it passes: each case above differs from this one by exactly one thing.
        KeyEventChain.Verify( Party, new[] { good }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
    }

    // --- Duplicity -------------------------------------------------------------------------------

    [Test]
    public void a_validly_signed_different_event_at_the_pinned_sequence_is_duplicity()
    {
        using var log = new Log( 2 );
        var pinned = log.Events[1];
        using var elsewhere = NewKey();
        // Whoever holds key 1 can write a second event 1, committing somewhere else.
        var fork = KeyEvent.Create( Party, 1, pinned.TimeName, log.Keys[1], Commit( elsewhere ), log.Events[0] );

        var c = KeyEventChain.Verify( Party, log.Tail( 0, 0 ).Append( fork ).ToList(), pinned );
        c.Verdict.ShouldBe( KeyChainVerdict.Duplicity );
        c.Held.ShouldBeSameAs( pinned );
        c.Conflicting.ShouldBeSameAs( fork );
    }

    [Test]
    public void a_forged_fork_is_invalid_not_duplicity()
    {
        // Duplicity raises an alert. Producing one must require the key, or anyone could page an operator.
        using var log = new Log( 2 );
        var pinned = log.Events[1];
        using var other = NewKey();

        var otherKey = Forge( 1, pinned.TimeName, other, other, Commit( other ), log.Events[0] );
        KeyEventChain.Verify( Party, new[] { otherKey }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );

        var badSignature = Forge( 1, pinned.TimeName, log.Keys[1], other, Commit( other ), log.Events[0] );
        KeyEventChain.Verify( Party, new[] { badSignature }, pinned ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
    }

    // --- Abandonment -----------------------------------------------------------------------------

    [Test]
    public void an_abandonment_ends_the_identity()
    {
        using var log = new Log( 3, abandonAtEnd: true );
        var last = log.Events[2];
        last.IsAbandonment.ShouldBeTrue();

        var c = KeyEventChain.Verify( Party, log.Tail( 0, 2 ), log.Events[1] );
        c.Verdict.ShouldBe( KeyChainVerdict.Abandoned );
        c.Head.ShouldBeSameAs( last );

        // Once pinned, nothing is accepted any more.
        KeyEventChain.Verify( Party, log.Tail( 0, 2 ), last ).Verdict.ShouldBe( KeyChainVerdict.Terminated );
        // And nothing can follow it: there is no committed key.
        last.CommitsTo( log.Keys[3].ExportSubjectPublicKeyInfo() ).ShouldBeFalse();
        Should.Throw<ArgumentException>( () => KeyEvent.Create( Party, 3, DateTime.UtcNow, log.Keys[3], Commit( log.Keys[3] ), last ) );
    }

    /// <summary>
    /// Builds an event the way an attacker would: any key revealed, any key signing, any predecessor.
    /// <see cref="KeyEvent.Create"/> refuses all of that, so this signs with a throw-away log and
    /// then swaps the bytes.
    /// </summary>
    static KeyEvent Forge( int seq,
                           DateTime timeName,
                           ECDsa revealed,
                           ECDsa signer,
                           byte[] nextCommit,
                           KeyEvent previous,
                           byte[]? prevDigest = null )
    {
        var spki = revealed.ExportSubjectPublicKeyInfo();
        var prev = prevDigest ?? previous.GetDigest( Party ).ToArray();
        var t = new DateTime( timeName.Ticks - (timeName.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc );

        // The signed payload, exactly as KeyEvent builds it.
        var name = System.Text.Encoding.UTF8.GetBytes( Party );
        var tag = "CK.AppIdentity.KEL/0"u8.ToArray();
        using var payload = new MemoryStream();
        using( var w = new BinaryWriter( payload, System.Text.Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( tag );
            w.Write( (ushort)name.Length );
            w.Write( name );
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( prev );
        }
        var hash = SHA512.HashData( payload.ToArray() );
        var sig = signer.SignHash( hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation );

        using var encoded = new MemoryStream();
        using( var w = new BinaryWriter( encoded ) )
        {
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( prev );
            w.Write( (byte)sig.Length );
            w.Write( sig );
        }
        return KeyEvent.Read( encoded.ToArray() );
    }
}
