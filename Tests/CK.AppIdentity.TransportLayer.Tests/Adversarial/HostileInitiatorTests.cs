using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Monitoring;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The harness as a hostile INITIATOR against a real listener.
/// <para>
/// This is the direction that faces the network: anyone who can reach the port can send whatever
/// they like, before any trust decision has been made. It is what the nonce replay cache (M1), the
/// clock-offset check and the bounded parsers defend.
/// </para>
/// </summary>
[TestFixture]
public class HostileInitiatorTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateListenerAsync( string localName, string knownRemote, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = knownRemote;
        }, ConfigureFastClock, token: token );

    byte[] BuildInitial( string claimedFullName, PeerIdentity key, ulong nonce )
    {
        // A fresh ephemeral per connection, exactly as a real initiator does.
        using var ephemeral = new PeerEphemeral();
        return PeerMessages.InitialMessage( claimedFullName,
                                        instanceId: "AdvInstance",
                                        availableProtocols: Array.Empty<string>(),
                                        expectedCommonProtocolCount: 0,
                                        nonceCreationTime: _systemClock.UtcNow,
                                        nonce: nonce,
                                        ephemeralPublicKey: ephemeral.PublicKey,
                                        macCapabilities: RunPhaseProtection.LocalCapabilities,
                                        signWith: new[] { key } );
    }

    static ulong NewNonce() => BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) );

    /// <summary>Reads a frame, or null when the listener simply closes on us.</summary>
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

    [Test, CancelAfter( 30000 )]
    public async Task A_hostile_initiator_gets_a_reply_for_a_known_party_Async( CancellationToken token )
    {
        // Baseline for this direction: a well-formed InitialMessage claiming a party the listener
        // knows must produce a reply. Without this, "no reply" in the replay test below would be
        // meaningless.
        const string remote = "$AdvInitA";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$AdvListenA", remote, token );
        using var key = PeerIdentity.Create();

        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() ), token );

        var reply = await ReadOrNullAsync( c, token );
        reply.ShouldNotBeNull( "A known party sending a well-formed, verifiable InitialMessage must get an answer." );
        reply!.Value.IsZeroProtocol.ShouldBeTrue();
        TestHelper.Monitor.Info( $"Listener replied with discriminator {reply.Value.Discriminator}." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_replayed_InitialMessage_is_rejected_Async( CancellationToken token )
    {
        // M1: the nonce replay cache. The exact same signed bytes, sent twice, must not both be
        // accepted — otherwise a captured handshake can be replayed inside the clock window.
        const string remote = "$AdvInitB";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$AdvListenB", remote, token );
        using var key = PeerIdentity.Create();

        // One message, sent twice verbatim.
        var initial = BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() );

        PeerWire.Frame2? first, second;
        await using( var c1 = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c1.SendZeroFrameAsync( initial, token );
            first = await ReadOrNullAsync( c1, token );
        }
        first.ShouldNotBeNull( "Sanity: the first copy must be processed." );
        first!.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalFailureMessage,
            "The first, legitimately signed copy from a known party must not be treated as a failure." );

        await using( var c2 = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c2.SendZeroFrameAsync( initial, token );
            second = await ReadOrNullAsync( c2, token );
        }

        // The listener answers a failed signature OR a failed nonce check with a deliberate one-byte
        // FinalFailure — it declines to spend CPU and bandwidth signing a reply to a peer that just
        // failed verification. So the evidence of rejection is the CHANGE of reply, not silence.
        second.ShouldNotBeNull();
        second!.Value.Discriminator.ShouldBe( PeerMessages.DNegoFinalFailureMessage,
            "The replayed InitialMessage carries a nonce already in the replay cache and must be " +
            "rejected. Accepting it would let a captured handshake be replayed inside the " +
            "clock-offset window (finding M1)." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_fresh_nonce_from_the_same_party_is_still_accepted_Async( CancellationToken token )
    {
        // Control for the replay test: the rejection above must be caused by the repeated NONCE,
        // not by the listener refusing a second connection from the same party for some other reason.
        const string remote = "$AdvInitC";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$AdvListenC", remote, token );
        using var key = PeerIdentity.Create();

        PeerWire.Frame2? first, second;
        await using( var c1 = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c1.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() ), token );
            first = await ReadOrNullAsync( c1, token );
        }
        await using( var c2 = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c2.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() ), token );
            second = await ReadOrNullAsync( c2, token );
        }

        first.ShouldNotBeNull();
        second.ShouldNotBeNull();
        second!.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalFailureMessage,
            "A DIFFERENT nonce from the same party must still be processed normally: the replay " +
            "test must reject for the repeated nonce, not merely for reconnecting." );
    }

    [TestCase( "truncated payload" )]
    [TestCase( "length lies" )]
    [TestCase( "garbage" )]
    [TestCase( "header only" )]
    [Test, CancelAfter( 30000 )]
    public async Task Malformed_input_does_not_take_the_listener_down_Async( string shape )
    {
        using var cts = new CancellationTokenSource( TimeSpan.FromSeconds( 25 ) );
        var token = cts.Token;

        const string remote = "$AdvInitD";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$AdvListenD", remote, token );
        using var key = PeerIdentity.Create();

        var good = BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() );

        await using( var bad = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            switch( shape )
            {
                case "truncated payload":
                    // A correct header announcing N bytes, followed by only half of them.
                    {
                        var frame = PeerWire.Frame( good );
                        await bad.SendRawAsync( frame.AsMemory( 0, frame.Length / 2 ), token );
                        break;
                    }
                case "length lies":
                    // Header claims a huge payload, nothing follows.
                    {
                        var header = new byte[PeerWire.MaxHeaderLength];
                        int n = PeerWire.WriteHeader( header, PeerWire.ZeroProtocolNumber, 100_000_000 );
                        await bad.SendRawAsync( header.AsMemory( 0, n ), token );
                        break;
                    }
                case "garbage":
                    await bad.SendRawAsync( RandomNumberGenerator.GetBytes( 512 ), token );
                    break;
                case "header only":
                    await bad.SendRawAsync( new byte[] { 0x00 }, token );
                    break;
            }
            // Drop the connection mid-stream, which is itself part of the attack.
        }

        // The listener must still serve a legitimate peer afterwards. This is the assertion that
        // matters: not "did it log an error" but "is it still alive".
        await using var ok = await AdversarialPeer.ConnectAsync( cancellation: token );
        await ok.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, NewNonce() ), token );
        var reply = await ReadOrNullAsync( ok, token );
        reply.ShouldNotBeNull( $"After '{shape}', the listener must still answer a well-formed peer." );
    }
}
