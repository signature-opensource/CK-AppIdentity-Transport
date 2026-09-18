using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M12: admission control for connections that have not authenticated yet.
/// <para>
/// A connection costs a pooled buffer, a task, a back task, an SPKI import and an ECDSA verification
/// before the listener knows whether it has ever heard of the peer — and it cannot skip that work for
/// an unknown party, because an unknown party knocking is the intended onboarding flow (M8).
/// <c>IncomingNegotiationTimeout</c> bounds how long one of those lasts. Nothing bounds how many run at once.
/// </para>
/// <para>
/// A peer that connects and then says nothing holds its slot for the full timeout, which is what these
/// tests use to fill the gate deterministically.
/// </para>
/// </summary>
[TestFixture]
public class NegotiationCapTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateListenerAsync( string name, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = $"${name}Peer";
        }, ConfigureFastClock, token: token );

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token, int seconds = 20 )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( !condition() )
        {
            if( DateTime.UtcNow > deadline ) Throw.CKException( $"Timeout while waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }

    /// <summary>Connects and says nothing: the negotiation holds its slot until it times out.</summary>
    static async Task<PeerConnection> SilentPeerAsync( CancellationToken token )
        => await AdversarialPeer.ConnectAsync( cancellation: token );

    /// <summary>
    /// Whether the listener drops this connection within <paramref name="ms"/> without a word.
    /// <para>
    /// This is THE observable that distinguishes refused from admitted, and the counters are not: a
    /// refused connection is closed at accept time, while an admitted silent one is held for the full
    /// <c>IncomingNegotiationTimeout</c> (2 s) waiting for an InitialMessage. Asserting only on
    /// <c>CurrentNegotiationCount</c>/<c>RefusedNegotiationCount</c> would pass even against a gate
    /// whose verdict is computed and then ignored: those counters are maintained inside the decision
    /// being tested, so they prove it was taken, not that it was obeyed.
    /// </para>
    /// </summary>
    static async Task<bool> IsDroppedWithinAsync( PeerConnection c, int ms, CancellationToken token )
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource( token );
        cts.CancelAfter( ms );
        try
        {
            await c.ReadFrameAsync( cts.Token );
            return false; // It said something: not a refusal.
        }
        catch( System.IO.EndOfStreamException ) { return true; }
        catch( System.IO.IOException ) { return true; }
        catch( System.Net.Sockets.SocketException ) { return true; }
        catch( OperationCanceledException ) { return false; } // Still open when the clock ran out.
    }

    [Test, CancelAfter( 60000 )]
    public async Task Concurrent_negotiations_are_capped_Async( CancellationToken token )
    {
        await using var listener = await CreateListenerAsync( "M12Cap", token );
        var f = listener.GetRequiredFeature<TransportManagerFeature>();
        f.MaxConcurrentNegotiation = 3;

        var peers = new List<PeerConnection>();
        try
        {
            for( int i = 0; i < 3; ++i ) peers.Add( await SilentPeerAsync( token ) );
            await WaitForAsync( () => f.CurrentNegotiationCount == 3, "the gate to fill", token );
            f.RefusedNegotiationCount.ShouldBe( 0, "Three is within the cap." );

            // The fourth is accepted by the OS and then closed by us without a byte being read.
            var fourth = await SilentPeerAsync( token );
            peers.Add( fourth );
            await WaitForAsync( () => f.RefusedNegotiationCount >= 1, "the fourth to be refused", token );

            f.CurrentNegotiationCount.ShouldBe( 3,
                "The refused connection took no slot: the cap is what bounds the unauthenticated work " +
                "in flight, and nothing beyond it may start." );

            // The behaviour, not just the bookkeeping.
            (await IsDroppedWithinAsync( fourth, 750, token )).ShouldBeTrue(
                "The refused connection is closed at accept time, long before IncomingNegotiationTimeout." );
            (await IsDroppedWithinAsync( peers[0], 750, token )).ShouldBeFalse(
                "An admitted one is held, waiting for its InitialMessage. Without this the test would " +
                "pass on a gate whose verdict is computed and ignored." );
        }
        finally
        {
            foreach( var p in peers ) await p.DisposeAsync();
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_negotiation_slot_is_released_when_the_connection_ends_Async( CancellationToken token )
    {
        // The half that matters more than the cap itself. A slot that is taken and never given back
        // tightens the cap permanently, so a listener would refuse everything after enough failures —
        // a denial of service built out of the defence against one.
        await using var listener = await CreateListenerAsync( "M12Release", token );
        var f = listener.GetRequiredFeature<TransportManagerFeature>();
        f.MaxConcurrentNegotiation = 3;

        for( int round = 0; round < 3; ++round )
        {
            var peers = new List<PeerConnection>();
            for( int i = 0; i < 3; ++i ) peers.Add( await SilentPeerAsync( token ) );
            await WaitForAsync( () => f.CurrentNegotiationCount == 3, $"the gate to fill (round {round})", token );

            // Dropping the connection ends the negotiation without waiting out IncomingNegotiationTimeout.
            foreach( var p in peers ) await p.DisposeAsync();
            await WaitForAsync( () => f.CurrentNegotiationCount == 0, $"the slots to come back (round {round})", token );
        }

        f.RefusedNegotiationCount.ShouldBe( 0,
            "Nine connections through a gate of three, and none was ever refused: every slot came back." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task One_source_cannot_take_every_slot_Async( CancellationToken token )
    {
        // Without a per-source limit, the global cap is a gift to a single attacker: fill it and every
        // legitimate peer is refused. Here the global cap has room to spare and the refusal comes from
        // the per-source limit alone.
        //
        // What this does NOT cover: that a DIFFERENT source still gets in. Everything here is loopback,
        // so there is only one source address to be had.
        await using var listener = await CreateListenerAsync( "M12Source", token );
        var f = listener.GetRequiredFeature<TransportManagerFeature>();
        f.MaxConcurrentNegotiation = 8;
        f.MaxConcurrentNegotiationPerSource = 2;

        var peers = new List<PeerConnection>();
        try
        {
            for( int i = 0; i < 4; ++i ) peers.Add( await SilentPeerAsync( token ) );
            await WaitForAsync( () => f.RefusedNegotiationCount >= 1, "the per-source limit to bite", token );

            f.CurrentNegotiationCount.ShouldBe( 2,
                "Refused at 2 from this source while 6 of the 8 global slots were free: one peer " +
                "cannot starve the others by opening connections." );
            (await IsDroppedWithinAsync( peers[3], 750, token )).ShouldBeTrue(
                "The third and fourth from this source are closed at accept time." );
        }
        finally
        {
            foreach( var p in peers ) await p.DisposeAsync();
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_refused_connection_does_not_disturb_the_listener_Async( CancellationToken token )
    {
        // Refusing must be a non-event: the listener keeps accepting, and a peer that arrives once a
        // slot is free negotiates normally. A cap that wedges the accept loop would be worse than none.
        await using var listener = await CreateListenerAsync( "M12After", token );
        var f = listener.GetRequiredFeature<TransportManagerFeature>();
        f.MaxConcurrentNegotiation = 2;

        var blockers = new List<PeerConnection>();
        for( int i = 0; i < 2; ++i ) blockers.Add( await SilentPeerAsync( token ) );
        await WaitForAsync( () => f.CurrentNegotiationCount == 2, "the gate to fill", token );

        await using( var refused = await SilentPeerAsync( token ) )
        {
            await WaitForAsync( () => f.RefusedNegotiationCount >= 1, "the refusal", token );
            (await IsDroppedWithinAsync( refused, 750, token )).ShouldBeTrue();
        }
        foreach( var p in blockers ) await p.DisposeAsync();
        await WaitForAsync( () => f.CurrentNegotiationCount == 0, "the slots to come back", token );

        // A real peer now, after the storm: it must get a real answer.
        using var key = PeerIdentity.Create();
        using var ephemeral = new PeerEphemeral();
        var initial = PeerMessages.InitialMessage( "Test/$M12AfterPeer/#Dev",
                                                   instanceId: "M12Instance",
                                                   availableProtocols: Array.Empty<string>(),
                                                   expectedCommonProtocolCount: 0,
                                                   nonceCreationTime: _systemClock.UtcNow,
                                                   nonce: BitConverter.ToUInt64( System.Security.Cryptography.RandomNumberGenerator.GetBytes( 8 ) ),
                                                   ephemeralPublicKey: ephemeral.PublicKey,
                                                   macCapabilities: RunPhaseProtection.LocalCapabilities,
                                                   signWith: new[] { key } );
        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( initial, token );
        var reply = await c.ReadFrameAsync( token );
        reply.IsZeroProtocol.ShouldBeTrue( "The listener is still serving after refusing connections." );
    }
}
