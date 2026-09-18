using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Pins the adversarial harness's independent framing against the production reader and writer.
/// <para>
/// This is the harness's own correctness test. Every adversarial result downstream is only
/// meaningful if the harness frames messages the way the real stack does — otherwise a rejected
/// attack proves nothing, because it may have been rejected as malformed rather than as hostile.
/// </para>
/// </summary>
[TestFixture]
public class PeerWireTests
{
    sealed class Ctx : IDisposable
    {
        public readonly MessageProtocol TestProtocol;
        public readonly MessageProtocolMap TestMap;
        public readonly OutgoingMessageFactory Outgoing;
        public readonly IncomingMessageFactory Incoming;

        public Ctx()
        {
            var dir = new MessageProtocolDirectoryService();
            dir.TryRegister( TestHelper.Monitor, "Test", 0, out TestProtocol! ).ShouldBeTrue();
            TestMap = MessageProtocolMap.Get( TestProtocol );
            Outgoing = new OutgoingMessageFactory( TestProtocol );
            Incoming = new IncomingMessageFactory( TestMap );
        }

        public void Dispose()
        {
            Outgoing.Dispose();
            Incoming.Dispose();
        }
    }

    /// <summary>
    /// Feeds an in-memory buffer to the production reader.
    /// </summary>
    sealed class ArrayReader
    {
        readonly byte[] _data;
        int _offset;
        public ArrayReader( byte[] data ) => _data = data;

        public ValueTask ReadExactlyAsync( Memory<byte> memory, CancellationToken cancellation )
        {
            _data.AsSpan( _offset, memory.Length ).CopyTo( memory.Span );
            _offset += memory.Length;
            return ValueTask.CompletedTask;
        }
    }

    // The interesting sizes are the length-prefix boundaries: 1-byte length up to 255, then the
    // reader's hard floor of 256, then the 2- and 3-byte length transitions.
    [TestCase( 1 )]
    [TestCase( 2 )]
    [TestCase( 254 )]
    [TestCase( 255 )]
    [TestCase( 256 )]
    [TestCase( 257 )]
    [TestCase( 4095 )]
    [TestCase( 4096 )]
    [TestCase( 4097 )]
    [TestCase( 65535 )]
    [TestCase( 65536 )]
    [TestCase( 65537 )]
    [TestCase( 200000 )]
    public async Task Harness_frames_are_read_by_the_production_reader_Async( int payloadLength )
    {
        using var ctx = new Ctx();
        var payload = RandomNumberGenerator.GetBytes( payloadLength );

        // Harness writes the frame; the REAL IncomingMessageFactory reads it back.
        var frame = PeerWire.Frame( payload, protocolNumber: 1 );
        var reader = new ArrayReader( frame );
        using var m = await ctx.Incoming.ReadAsync( reader.ReadExactlyAsync );

        m.IsValid.ShouldBeTrue( $"Payload of {payloadLength} bytes must round-trip." );
        m.Protocol.ShouldBe( ctx.TestProtocol );
        m.Message.ToArray().ShouldBe( payload );
    }

    [TestCase( 1 )]
    [TestCase( 255 )]
    [TestCase( 256 )]
    [TestCase( 65536 )]
    [TestCase( 200000 )]
    public async Task Production_frames_are_read_by_the_harness_Async( int payloadLength )
    {
        using var ctx = new Ctx();
        var payload = RandomNumberGenerator.GetBytes( payloadLength );

        // The REAL writer produces the frame; the harness reads it back.
        using var m = ctx.Outgoing.Create( bytes =>
        {
            var w = new FastByteWriter( bytes );
            w.WriteBytes( payload );
            w.Commit();
        } );
        var bytes = new byte[m.Message.Length + IOutgoingMessage.MaxWirePrefixLength];
        int lenHeader = IOutgoingMessage.WriteWireHeader( ctx.TestMap, m, bytes );
        m.Message.CopyTo( bytes.AsSpan( lenHeader ) );

        using var s = new MemoryStream( bytes, 0, lenHeader + (int)m.Message.Length );
        var frame = await PeerWire.ReadFrameAsync( s );

        frame.ProtocolNumber.ShouldBe( 1u );
        frame.IsControl.ShouldBeFalse();
        frame.Payload.ShouldBe( payload );
    }

    [Test]
    public void Header_length_matches_the_production_encoding()
    {
        // MaxWirePrefixLength is 5: 1 flag byte + up to 4 length bytes.
        PeerWire.MaxHeaderLength.ShouldBe( IOutgoingMessage.MaxWirePrefixLength );

        Span<byte> h = stackalloc byte[PeerWire.MaxHeaderLength];
        PeerWire.WriteHeader( h, 0, 0 ).ShouldBe( 2, "Empty message is 2 bytes on the wire." );
        PeerWire.WriteHeader( h, 0, 255 ).ShouldBe( 2, "A 1-byte length covers up to 255." );
        PeerWire.WriteHeader( h, 0, 256 ).ShouldBe( 3 );
        PeerWire.WriteHeader( h, 0, 65535 ).ShouldBe( 3 );
        PeerWire.WriteHeader( h, 0, 65536 ).ShouldBe( 4 );
        PeerWire.WriteHeader( h, 0, (1u << 24) - 1 ).ShouldBe( 4 );
        PeerWire.WriteHeader( h, 0, 1u << 24 ).ShouldBe( 5 );
    }

    [Test]
    public void Control_flag_and_protocol_number_round_trip()
    {
        Span<byte> h = stackalloc byte[PeerWire.MaxHeaderLength];
        PeerWire.WriteHeader( h, protocolNumber: 5, payloadLength: 10, isControl: true );
        (h[0] & 0b111).ShouldBe( 5 );
        (h[0] & PeerWire.IsControlFlag).ShouldNotBe( 0 );

        PeerWire.WriteHeader( h, protocolNumber: 5, payloadLength: 10, isControl: false );
        (h[0] & PeerWire.IsControlFlag).ShouldBe( 0 );
    }
}
