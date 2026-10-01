using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// End-to-end coverage of BOTH MAC primitives.
/// <para>
/// This exists because of a gap that would otherwise be invisible: the development and CI machines
/// have AES-NI, so every real connection negotiates AES-GMAC and the HMAC path never runs. HMAC is
/// the fallback for machines without AES-NI — which, for this product, is hardware nobody has
/// surveyed. Leaving the path that runs on unknown hardware untested end to end is exactly the
/// "the security-critical path is the less-exercised one" risk the design warns about.
/// </para>
/// </summary>
[TestFixture]
public class MacNegotiationTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    [TearDown]
    public void ResetCapabilities() => RunPhaseProtection.CapabilityRestriction = null;

    [Test]
    public void The_restriction_can_only_remove_capabilities()
    {
        RunPhaseProtection.CapabilityRestriction = RunPhaseProtection.HmacOnly;
        RunPhaseProtection.LocalCapabilities.ShouldBe( RunPhaseProtection.HmacOnly );
        RunPhaseProtection.Select( 0xFF ).ShouldBe( MacAlgorithm.HmacSha256,
            "A restricted process must not select a primitive it stopped advertising." );

        // It cannot claim what the hardware cannot do: the value is masked by the hardware set.
        RunPhaseProtection.CapabilityRestriction = 0xFF;
        RunPhaseProtection.LocalCapabilities.ShouldBe( RunPhaseProtection.HardwareCapabilities );

        // And it cannot leave the process unable to speak at all.
        Should.Throw<ArgumentException>( () => RunPhaseProtection.CapabilityRestriction = 0 );
    }

    [TestCase( true )]
    [TestCase( false )]
    [CancelAfter( 30000 )]
    public async Task Two_real_peers_connect_with_either_primitive_Async( bool forceHmac, CancellationToken token )
    {
        // The whole point: run a genuine TCP handshake and run-phase exchange under BOTH primitives,
        // so the fallback is known to work rather than assumed to.
        if( forceHmac ) RunPhaseProtection.CapabilityRestriction = RunPhaseProtection.HmacOnly;
        var expected = forceHmac ? MacAlgorithm.HmacSha256 : MacAlgorithm.AesGmac;
        if( !forceHmac && (RunPhaseProtection.HardwareCapabilities & (1 << (int)MacAlgorithm.AesGmac)) == 0 )
        {
            Assert.Ignore( "This machine has no AES-NI: the GMAC case cannot be exercised here." );
        }

        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/$MacListen{forceHmac}";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = $"$MacSend{forceHmac}";
        }, ConfigureFastClock, token: token );

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/$MacSend{forceHmac}";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = $"$MacListen{forceHmac}";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{AdversarialPeer.DefaultListenerPort}";
        }, ConfigureFastClock, token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await senderTransport.ReadyTask.WaitAsync( token );
        await listenerTransport.ReadyTask.WaitAsync( token );

        senderTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected,
            $"A full handshake and run phase must work under {expected}." );
        listenerTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );

        // Assert the primitive, not just the connection. Without this the HMAC case could pass
        // while quietly negotiating GMAC, and the fallback path would remain untested.
        senderTransport.NegotiatedMacAlgorithm.ShouldBe( expected );
        listenerTransport.NegotiatedMacAlgorithm.ShouldBe( expected, "Both peers must agree on the primitive." );
        senderTransport.SessionId.ShouldBe( listenerTransport.SessionId,
            "Both peers derive the same session keys, so they must report the same session id." );

        TestHelper.Monitor.Info( $"Connected using {expected}, session {senderTransport.SessionId}." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_peer_without_AES_pulls_the_connection_down_to_HMAC_Async( CancellationToken token )
    {
        // The asymmetric case, which the in-process test above cannot produce because both peers
        // share this process's capabilities: the harness advertises HMAC only, while the real
        // initiator advertises everything its hardware supports. The connection must still come up,
        // on the primitive the weaker side can run.
        const string remote = "$AdvMacFloor";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        using var ephemeral = new PeerEphemeral();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$MacFloor";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var connection = await peer.AcceptAsync( token );
        var initial = await connection.ReadInitialMessageAsync( token );

        // What the initiator offered, and what a peer restricted to HMAC would pick from it.
        (initial.MacCapabilities & RunPhaseProtection.HmacOnly).ShouldNotBe( (byte)0,
            "Every peer must always be able to run HMAC: it is the floor that makes agreement possible." );

        var reply = PeerMessages.AcceptedProtocols( initial.Nonce,
                                                    TimeSpan.Zero,
                                                    _systemClock.UtcNow,
                                                    initial.AvailableProtocols,
                                                    ephemeral.PublicKey,
                                                    MacAlgorithm.HmacSha256,   // our "hardware" cannot do GMAC
                                                    new[] { peerKey } );
        await connection.SendZeroFrameAsync( reply, token );

        (await connection.ReadFrameAsync( token )).Discriminator
            .ShouldBe( PeerMessages.DNegoFinalSuccessMessage,
                "An initiator that supports GMAC must still accept a peer that can only do HMAC." );

        await feature.ReadyTask.WaitAsync( token );
        feature.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_peer_selecting_an_unoffered_algorithm_is_refused_Async( CancellationToken token )
    {
        // The downgrade attempt the capability model exists to block: the listener echoes an
        // algorithm the initiator never advertised. Selection is a floor, not a free choice.
        const string remote = "$AdvMacBogus";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        using var ephemeral = new PeerEphemeral();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$MacBogus";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        await using var connection = await peer.AcceptAsync( token );
        var initial = await connection.ReadInitialMessageAsync( token );

        var reply = PeerMessages.AcceptedProtocols( initial.Nonce,
                                                    TimeSpan.Zero,
                                                    _systemClock.UtcNow,
                                                    initial.AvailableProtocols,
                                                    ephemeral.PublicKey,
                                                    MacAlgorithm.Invalid,   // never offered, and cannot be
                                                    new[] { peerKey } );
        await connection.SendZeroFrameAsync( reply, token );

        var answer = await ReadOrNullAsync( connection, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                "An algorithm we never advertised must not be accepted: 'Invalid' exists precisely so " +
                "that a zero byte on the wire is rejected instead of quietly meaning something." );
        }
    }

    static async Task<PeerWire.Frame2?> ReadOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try
        {
            return await c.ReadFrameAsync( token );
        }
        catch( System.IO.EndOfStreamException ) { return null; }
        catch( System.IO.IOException ) { return null; }
        catch( System.Net.Sockets.SocketException ) { return null; }
    }
}
