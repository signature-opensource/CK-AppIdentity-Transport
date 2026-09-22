using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The run-phase integrity core (C1-b): ephemeral ECDH, HKDF to two directional keys, and a MAC
/// over a monotonic counter.
/// <para>
/// These tests exercise the primitive directly, before it is wired into the protocol. Everything
/// that makes AES-GMAC safe here is a property of this class — fresh keys per connection, distinct
/// keys per direction, a counter that only moves forward — so each of those is asserted rather
/// than assumed.
/// </para>
/// </summary>
[TestFixture]
public class RunPhaseProtectionTests
{
    static readonly byte[] _transcript = RunPhaseProtection.BuildTranscript(
        RunPhaseProtection.LocalCapabilities, RunPhaseProtection.LocalCapabilities, MacAlgorithm.AesGmac, 0, "Test/$A/#Dev", "Test/$B/#Dev" );

    /// <summary>
    /// Performs the two-sided derivation exactly as the handshake will.
    /// </summary>
    static (RunPhaseProtection Initiator, RunPhaseProtection Listener) Handshake( MacAlgorithm alg,
                                                                                  ulong nonce = 0xDEADBEEF,
                                                                                  byte[]? transcript = null )
    {
        transcript ??= _transcript;
        using var a = RunPhaseProtection.CreateEphemeral();
        using var b = RunPhaseProtection.CreateEphemeral();
        var aPub = a.PublicKey.ExportSubjectPublicKeyInfo();
        var bPub = b.PublicKey.ExportSubjectPublicKeyInfo();
        var initiator = RunPhaseProtection.Derive( a, bPub, alg, nonce, transcript, isInitiator: true );
        var listener = RunPhaseProtection.Derive( b, aPub, alg, nonce, transcript, isInitiator: false );
        return (initiator, listener);
    }

    static ReadOnlySequence<byte> Seq( byte[] b ) => new ReadOnlySequence<byte>( b );

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void Both_sides_derive_matching_keys_and_frames_verify( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 300 );
            var tag = new byte[RunPhaseProtection.TagLength];

            i.SignNext( header, Seq( payload ), tag );
            l.VerifyNext( header, Seq( payload ), tag ).ShouldBeTrue(
                "ECDH must give both sides the same secret, and the listener must verify with the " +
                "initiator-to-listener key." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void An_altered_payload_is_rejected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 300 );
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, Seq( payload ), tag );

            payload[100] ^= 0xFF;
            l.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse( "One flipped bit must be caught." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void An_altered_header_is_rejected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 50 );
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, Seq( payload ), tag );

            // Retargeting a frame at another protocol must not be possible either.
            l.VerifyNext( new byte[] { 0x02, 0x10 }, Seq( payload ), tag ).ShouldBeFalse();
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void An_altered_declared_length_is_rejected( MacAlgorithm alg )
    {
        // The whole header is covered, not just its flag byte. A tampered declared length would
        // also be caught indirectly — it changes how many payload bytes the receiver feeds in —
        // but indirect coverage is an argument, and this asserts the direct property instead.
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x41, 0x00, 0x01 };   // lenSize=1: two length bytes follow
            var payload = RandomNumberGenerator.GetBytes( 256 );
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, Seq( payload ), tag );

            var lying = new byte[] { 0x41, 0x01, 0x01 };    // same flags, different declared length
            l.VerifyNext( lying, Seq( payload ), tag ).ShouldBeFalse(
                "The declared length is part of the authenticated frame." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void Headers_of_different_lengths_do_not_collide( MacAlgorithm alg )
    {
        // The GMAC nonce zero-pads the header to 5 bytes, so a 2-byte and a 3-byte header could in
        // principle pad to the same value. They cannot: byte 0 encodes the length size, so headers
        // of different lengths already differ there. Asserted rather than reasoned about.
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var payload = RandomNumberGenerator.GetBytes( 32 );
            var shortHeader = new byte[] { 0x01, 0x20 };
            var longHeader = new byte[] { 0x41, 0x20, 0x00 };
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( shortHeader, Seq( payload ), tag );
            l.VerifyNext( longHeader, Seq( payload ), tag ).ShouldBeFalse();
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void A_replayed_frame_is_rejected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 50 );
            var tag = new byte[RunPhaseProtection.TagLength];

            i.SignNext( header, Seq( payload ), tag );
            l.VerifyNext( header, Seq( payload ), tag ).ShouldBeTrue();
            // The counter has moved on: the same bytes can never be accepted again.
            l.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse(
                "A replayed frame must fail: the receive counter has advanced." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void Reordered_frames_are_rejected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var first = RandomNumberGenerator.GetBytes( 10 );
            var second = RandomNumberGenerator.GetBytes( 10 );
            var tag1 = new byte[RunPhaseProtection.TagLength];
            var tag2 = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, Seq( first ), tag1 );
            i.SignNext( header, Seq( second ), tag2 );

            // Delivering the second frame first must fail: this is what a MAC alone would miss.
            l.VerifyNext( header, Seq( second ), tag2 ).ShouldBeFalse( "Out-of-order delivery must be caught." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void A_dropped_frame_is_detected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var tag = new byte[RunPhaseProtection.TagLength];
            var dropped = RandomNumberGenerator.GetBytes( 10 );
            var next = RandomNumberGenerator.GetBytes( 10 );
            i.SignNext( header, Seq( dropped ), tag );      // never delivered
            i.SignNext( header, Seq( next ), tag );

            l.VerifyNext( header, Seq( next ), tag ).ShouldBeFalse(
                "Silently dropping a frame must not go unnoticed: the counters diverge." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void Reflecting_our_own_frame_back_at_us_is_rejected( MacAlgorithm alg )
    {
        var (i, l) = Handshake( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 50 );
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, Seq( payload ), tag );

            // The initiator must not accept a frame it signed itself: the two directions use
            // different keys precisely so that this cannot work.
            i.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse( "Reflection must be impossible." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void A_frame_from_a_different_session_is_rejected( MacAlgorithm alg )
    {
        // Cross-connection splicing: a frame captured from one connection, injected into another
        // between the same two parties.
        var (i1, l1) = Handshake( alg );
        var (i2, l2) = Handshake( alg );
        using( i1 )
        using( l1 )
        using( i2 )
        using( l2 )
        {
            i1.SessionId.ShouldNotBe( i2.SessionId,
                "Each connection must derive its own keys: a shared key would make GMAC's nonce " +
                "reuse possible and is forbidden outright." );

            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 50 );
            var tag = new byte[RunPhaseProtection.TagLength];
            i1.SignNext( header, Seq( payload ), tag );

            l2.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse(
                "A frame from another session must not verify here." );
        }
    }

    [Test]
    public void A_tampered_transcript_makes_the_two_sides_derive_different_keys()
    {
        // This is the property that makes the capability advertisement safe without an explicit
        // "was the negotiation modified?" check: tampering simply produces different keys, so the
        // first frame fails. It fails closed.
        using var a = RunPhaseProtection.CreateEphemeral();
        using var b = RunPhaseProtection.CreateEphemeral();
        var aPub = a.PublicKey.ExportSubjectPublicKeyInfo();
        var bPub = b.PublicKey.ExportSubjectPublicKeyInfo();

        var honest = RunPhaseProtection.BuildTranscript( 0b110, 0b110, MacAlgorithm.AesGmac, 0, "Test/$A/#Dev", "Test/$B/#Dev" );
        // An attacker strips the GMAC capability bit, trying to force the weaker primitive.
        var tampered = RunPhaseProtection.BuildTranscript( 0b100, 0b110, MacAlgorithm.AesGmac, 0, "Test/$A/#Dev", "Test/$B/#Dev" );

        using var i = RunPhaseProtection.Derive( a, bPub, MacAlgorithm.AesGmac, 42, honest, true );
        using var l = RunPhaseProtection.Derive( b, aPub, MacAlgorithm.AesGmac, 42, tampered, false );

        i.SessionId.ShouldNotBe( l.SessionId );

        var header = new byte[] { 0x01, 0x10 };
        var payload = RandomNumberGenerator.GetBytes( 20 );
        var tag = new byte[RunPhaseProtection.TagLength];
        i.SignNext( header, Seq( payload ), tag );
        l.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse(
            "A modified transcript must break the very first frame." );
    }

    [Test]
    public void The_listener_capability_byte_is_bound_into_the_transcript_Async()
    {
        // The half that used to be missing. Only the initiator's capabilities entered the transcript,
        // so the initiator could verify that the selection was one IT offered but had no way to know
        // the listener could have done better - a downgrade lever the day a third, weaker primitive
        // is added. Now a difference in the LISTENER byte alone changes the derived keys.
        using var a = RunPhaseProtection.CreateEphemeral();
        using var b = RunPhaseProtection.CreateEphemeral();
        var aPub = a.PublicKey.ExportSubjectPublicKeyInfo();
        var bPub = b.PublicKey.ExportSubjectPublicKeyInfo();

        var honest = RunPhaseProtection.BuildTranscript( 0b110, 0b110, MacAlgorithm.AesGmac, 0, "Test/$A/#Dev", "Test/$B/#Dev" );
        // Same initiator byte, same selection, same names: ONLY the listener's advertisement differs.
        var tampered = RunPhaseProtection.BuildTranscript( 0b110, 0b100, MacAlgorithm.AesGmac, 0, "Test/$A/#Dev", "Test/$B/#Dev" );
        honest.ShouldNotBe( tampered );

        using var i = RunPhaseProtection.Derive( a, bPub, MacAlgorithm.AesGmac, 42, honest, true );
        using var l = RunPhaseProtection.Derive( b, aPub, MacAlgorithm.AesGmac, 42, tampered, false );
        i.SessionId.ShouldNotBe( l.SessionId );

        var header = new byte[] { 0x01, 0x10 };
        var payload = RandomNumberGenerator.GetBytes( 20 );
        var tag = new byte[RunPhaseProtection.TagLength];
        i.SignNext( header, Seq( payload ), tag );
        l.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse(
            "Changing only the listener's advertised capabilities must break the first frame." );
    }

    [Test]
    public void A_different_nonce_gives_different_keys()
    {
        var (i1, _) = Handshake( MacAlgorithm.AesGmac, nonce: 1 );
        var (i2, _) = Handshake( MacAlgorithm.AesGmac, nonce: 2 );
        using( i1 )
        using( i2 )
        {
            i1.SessionId.ShouldNotBe( i2.SessionId );
        }
    }

    [Test]
    public void Capability_selection_prefers_GMAC_and_never_yields_Invalid_between_real_peers()
    {
        const byte hmacOnly = 1 << (int)MacAlgorithm.HmacSha256;
        const byte both = (1 << (int)MacAlgorithm.HmacSha256) | (1 << (int)MacAlgorithm.AesGmac);

        RunPhaseProtection.Select( both ).ShouldBe(
            System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported
                ? MacAlgorithm.AesGmac
                : MacAlgorithm.HmacSha256 );

        RunPhaseProtection.Select( hmacOnly ).ShouldBe( MacAlgorithm.HmacSha256,
            "A peer without AES-NI must pull the connection down to HMAC, which every machine can run." );

        RunPhaseProtection.Select( 0 ).ShouldBe( MacAlgorithm.Invalid,
            "A peer advertising nothing must not be accommodated." );

        // HmacSha256 is unconditional: two real peers always share at least it.
        (RunPhaseProtection.LocalCapabilities & hmacOnly).ShouldNotBe( 0 );
    }

    [Test]
    public void Many_frames_verify_in_sequence()
    {
        // Exercises counter advance on both sides over a long run, and payloads that span the
        // interesting sizes.
        var (i, l) = Handshake( MacAlgorithm.AesGmac );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var tag = new byte[RunPhaseProtection.TagLength];
            for( int n = 0; n < 500; ++n )
            {
                var payload = RandomNumberGenerator.GetBytes( n % 300 );
                i.SignNext( header, Seq( payload ), tag );
                l.VerifyNext( header, Seq( payload ), tag ).ShouldBeTrue( $"Frame #{n} must verify." );
            }
        }
    }

    [Test]
    public void Multi_segment_payloads_verify()
    {
        // Run-phase payloads arrive as multi-segment sequences (4 KiB then 64 KiB), so the MAC must
        // walk the segments rather than assume a contiguous buffer.
        var (i, l) = Handshake( MacAlgorithm.AesGmac );
        using( i )
        using( l )
        {
            var data = RandomNumberGenerator.GetBytes( 10000 );
            var multi = Segmented( data, 4096 );
            multi.IsSingleSegment.ShouldBeFalse();

            var header = new byte[] { 0x01, 0x10 };
            var tag = new byte[RunPhaseProtection.TagLength];
            i.SignNext( header, multi, tag );
            l.VerifyNext( header, Seq( data ), tag ).ShouldBeTrue(
                "The same bytes must verify whether they arrive in one segment or several." );
        }
    }

    sealed class Seg : ReadOnlySequenceSegment<byte>
    {
        public Seg( ReadOnlyMemory<byte> m, long i ) { Memory = m; RunningIndex = i; }
        public Seg Append( ReadOnlyMemory<byte> m )
        {
            var n = new Seg( m, RunningIndex + Memory.Length );
            Next = n;
            return n;
        }
    }

    static ReadOnlySequence<byte> Segmented( byte[] data, int size )
    {
        var first = new Seg( data.AsMemory( 0, Math.Min( size, data.Length ) ), 0 );
        var last = first;
        for( int o = size; o < data.Length; o += size ) last = last.Append( data.AsMemory( o, Math.Min( size, data.Length - o ) ) );
        return new ReadOnlySequence<byte>( first, 0, last, last.Memory.Length );
    }
}
