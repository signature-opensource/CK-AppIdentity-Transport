using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using System.Buffers;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;
using CK.Testing.AppIdentity.TransportLayer;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M5: the declared length of an incoming run-phase message must be bounded.
/// <para>
/// That length is chosen by the peer, in a 5-byte header. Accepting <see cref="int.MaxValue"/> lets
/// a hostile peer ask for a 2 GiB buffer for free — and authenticating frames is no defence, because
/// the allocation happens <em>before</em> the MAC can reject them.
/// </para>
/// </summary>
[TestFixture]
public class MessageLengthBoundTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    /// <summary>
    /// Feeds a header claiming <paramref name="declaredLength"/> bytes and then refuses to supply
    /// them: if the reader tries to honour the claim, it blocks or allocates. A correct reader
    /// rejects on the header alone.
    /// </summary>
    sealed class LyingReader
    {
        readonly byte[] _head;
        int _offset;
        public bool ReadPastHeader { get; private set; }

        public LyingReader( byte[] head ) => _head = head;

        public ValueTask ReadExactlyAsync( Memory<byte> memory, CancellationToken cancellation )
        {
            if( _offset + memory.Length > _head.Length )
            {
                // The reader is asking for payload we never promised to deliver.
                ReadPastHeader = true;
                memory.Span.Clear();
                _offset += memory.Length;
                return ValueTask.CompletedTask;
            }
            _head.AsSpan( _offset, memory.Length ).CopyTo( memory.Span );
            _offset += memory.Length;
            return ValueTask.CompletedTask;
        }
    }

    [TestCase( int.MaxValue )]
    [TestCase( 1_000_000_000 )]
    [TestCase( MessageProtocol.DefaultMaxIncomingMessageLength + 1 )]
    public async Task An_oversized_declared_length_is_refused_Async( int declaredLength )
    {
        var dir = new MessageProtocolDirectoryService();
        dir.TryRegister( TestHelper.Monitor, "Test", 0, out var protocol ).ShouldBeTrue();
        protocol!.MaxIncomingMessageLength.ShouldBe( MessageProtocol.DefaultMaxIncomingMessageLength );

        using var incoming = new IncomingMessageFactory( MessageProtocolMap.Get( protocol ) );

        // A header claiming a huge payload, followed by the 256 bytes the reader pre-reads.
        var head = new byte[PeerWire.MaxHeaderLength + 256];
        int lenHeader = PeerWire.WriteHeader( head, protocolNumber: 1, payloadLength: (uint)declaredLength );
        var reader = new LyingReader( head.AsMemory( 0, lenHeader + 256 ).ToArray() );

        using var m = await incoming.ReadAsync( reader.ReadExactlyAsync );

        m.ShouldBeSameAs( IncomingMessage.Invalid,
            $"A declared length of {declaredLength} exceeds the protocol's cap and must be refused " +
            $"on the header alone, before anything is allocated for it." );
    }

    [Test]
    public async Task A_length_within_the_cap_is_still_accepted_Async()
    {
        // Control: the bound must not break legitimate traffic.
        var dir = new MessageProtocolDirectoryService();
        dir.TryRegister( TestHelper.Monitor, "Test", 0, out var protocol ).ShouldBeTrue();
        using var incoming = new IncomingMessageFactory( MessageProtocolMap.Get( protocol! ) );

        var payload = RandomNumberGenerator.GetBytes( 100_000 );
        var frame = PeerWire.Frame( payload, protocolNumber: 1 );
        var reader = new LyingReader( frame );

        using var m = await incoming.ReadAsync( reader.ReadExactlyAsync );
        m.IsValid.ShouldBeTrue();
        m.Message.ToArray().ShouldBe( payload );
    }

    [Test]
    public void A_channel_can_raise_its_own_cap()
    {
        var dir = new MessageProtocolDirectoryService();
        dir.TryRegister( TestHelper.Monitor, "Big", 0, out var big, maxIncomingMessageLength: 512 * 1024 * 1024 ).ShouldBeTrue();
        big!.MaxIncomingMessageLength.ShouldBe( 512 * 1024 * 1024,
            "A channel that legitimately carries large messages must be able to raise the bound." );

        // The Zero Protocol has its own, tighter cap: its run-phase traffic is tiny, and the
        // handshake messages it also carries are the largest thing it ever sees.
        MessageProtocol.ZeroProtocol.MaxIncomingMessageLength
            .ShouldBe( MessageProtocol.ZeroProtocolMaxIncomingMessageLength );
        MessageProtocol.ZeroProtocol.MaxIncomingMessageLength
            .ShouldBeLessThan( MessageProtocol.DefaultMaxIncomingMessageLength );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_real_listener_refuses_an_oversized_frame_and_survives_Async( CancellationToken token )
    {
        // End to end: a hostile initiator claims a 2 GiB handshake message. The listener must not
        // try to hold it, and must still serve a well-formed peer afterwards.
        const string remote = "$AdvHuge";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$LenListen";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = remote;
        }, ConfigureFastClock, token: token );

        using var key = PeerIdentity.Create();

        await using( var hostile = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            var header = new byte[PeerWire.MaxHeaderLength];
            int n = PeerWire.WriteHeader( header, PeerWire.ZeroProtocolNumber, payloadLength: int.MaxValue );
            await hostile.SendRawAsync( header.AsMemory( 0, n ), token );
            // Send a little, then vanish: a reader that believed the claim would sit on a 2 GiB buffer.
            await hostile.SendRawAsync( RandomNumberGenerator.GetBytes( 300 ), token );
        }

        await using var ok = await AdversarialPeer.ConnectAsync( cancellation: token );
        using var ephemeral = new PeerEphemeral();
        var initial = PeerMessages.InitialMessage( $"Test/{remote}/#Dev",
                                                   "LenInstance",
                                                   Array.Empty<string>(),
                                                   0,
                                                   _systemClock.UtcNow,
                                                   BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) ),
                                                   ephemeral.PublicKey,
                                                   RunPhaseProtection.LocalCapabilities,
                                                   new[] { key } );
        await ok.SendZeroFrameAsync( initial, token );

        var reply = await ok.ReadFrameAsync( token );
        reply.IsZeroProtocol.ShouldBeTrue(
            "After refusing a 2 GiB claim the listener must still answer a well-formed peer." );
    }

    [Test]
    public void The_sender_queue_is_bounded()
    {
        // M5's other half: an unbounded sender queue let producers grow memory without limit while
        // a remote was down, then flooded everything out on reconnect. The bound is what turns that
        // into back-pressure.
        TransportFeature.SenderQueueCapacity.ShouldBeGreaterThan( 0 );
        TransportFeature.SenderQueueCapacity.ShouldBeLessThan( int.MaxValue );
    }
}
