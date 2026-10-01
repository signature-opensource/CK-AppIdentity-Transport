using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Monitoring;
using System.Collections.Generic;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;
using CK.Testing.AppIdentity.TransportLayer;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M14: reconnection had no back-off across connections.
/// <para>
/// The per-attempt back-off lived on <c>OutgoingConnectionBackTask</c>, which is created fresh for
/// each reconnection and pooled, and whose <c>OnInitialize</c> zeroes the try count. So it only ever
/// applied to consecutive failures to <em>connect</em>. A peer that accepts, negotiates and then
/// drops us came back through <c>KillTransport(transport, 0)</c> — a brand new task, count zero,
/// delay zero — and the cycle ran as fast as the network allowed.
/// </para>
/// <para>
/// That cycle is the expensive one: a full negotiation is two signatures and two verifications per
/// side. An unfriendly peer holds both ends in it for free, and the logs fill on both.
/// </para>
/// </summary>
[TestFixture]
public class ReconnectBackOffTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateSenderAsync( string name, string remoteName, string address, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = remoteName;
            c["Parties:0:Address"] = address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

    /// <summary>
    /// Accepts one connection and takes it all the way to a VALIDATED transport: the initiator only
    /// attaches a controller once it has sent FinalSuccess, and only a validated transport reaches
    /// the reconnection path this finding is about. Returns after dropping it.
    /// </summary>
    async Task<bool> AcceptNegotiateAndDropAsync( AdversarialPeer peer, PeerIdentity peerKey, int holdMs, CancellationToken token )
    {
        await using var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );
        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { peerKey } ), token );
        var final = await c.ReadFrameAsync( token );
        if( holdMs > 0 ) await Task.Delay( holdMs, token );
        // Disposing drops the connection: the initiator kills a validated transport.
        return final.Discriminator == PeerMessages.DNegoFinalSuccessMessage;
    }

    [Test, CancelAfter( 120000 )]
    public async Task A_peer_that_drops_us_after_negotiating_is_backed_off_Async( CancellationToken token )
    {
        // The loop, measured. Heartbeats are 50 ms here, so the back-off sequence 1,2,4,8,16,30
        // heartbeats is 50,100,200,400,800,1500 ms: about 6 connections in 3 seconds. Without a
        // back-off the cycle is bounded only by a TCP connect plus a handshake.
        // The trust store is keyed by REMOTE NAME alone, so a key pinned by a previous run of this

        // test would be compared against this run's fresh one and the handshake would fail.

        PeerStore.ClearRemoteTrust( "Test/$M14FlapPeer" );
        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        await using var sender = await CreateSenderAsync( "M14Flap", "$M14FlapPeer", peer.Address, token );

        // Count ACCEPTED connections, not completed handshakes: each accept is one reconnection, and
        // that is the cost being bounded. Under a storm the initiator ends up with overlapping
        // transports and starts answering FinalFailure, so requiring every round to reach
        // FinalSuccess would make an unthrottled implementation fail on the wrong assertion, with a
        // message telling the reader nothing about back-off.
        int accepted = 0, negotiated = 0;
        var sw = Stopwatch.StartNew();
        while( sw.ElapsedMilliseconds < 3000 )
        {
            using var round = CancellationTokenSource.CreateLinkedTokenSource( token );
            round.CancelAfter( (int)Math.Max( 200, 3000 - sw.ElapsedMilliseconds ) );
            try
            {
                ++accepted;
                if( await AcceptNegotiateAndDropAsync( peer, peerKey, 0, round.Token ) ) ++negotiated;
            }
            catch( OperationCanceledException ) { --accepted; break; }
            catch( Exception ex )
            {
                TestContext.Out.WriteLine( $"Round ended early: {ex.GetType().Name}." );
            }
        }
        sw.Stop();
        TestContext.Out.WriteLine( $"Accepted {accepted} connections ({negotiated} fully negotiated) in {sw.ElapsedMilliseconds} ms." );

        negotiated.ShouldBeGreaterThan( 0,
            "Sanity: at least one connection must reach FinalSuccess, otherwise the transport never " +
            "becomes valid and this exercises the cheap connect-failure path instead of this finding." );
        accepted.ShouldBeLessThanOrEqualTo( 12,
            $"A peer that negotiates and then drops us must be backed off. Got {accepted} full " +
            "negotiations in 3 seconds; with no back-off the cycle repeats as fast as the handshake " +
            "completes, and each one costs two signatures and two verifications per side." );

        var f = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        f.FlapCount.ShouldBeGreaterThan( 1, "The flap count survives across transports, which is the fix." );
    }

    [Test, CancelAfter( 120000 )]
    public async Task A_connection_that_lasts_clears_the_flap_count_Async( CancellationToken token )
    {
        // The back-off must not be a ratchet. A remote that misbehaves and then settles has to get
        // its prompt reconnection back, or one bad patch would slow it down until the process
        // restarts.
        // The trust store is keyed by REMOTE NAME alone, so a key pinned by a previous run of this

        // test would be compared against this run's fresh one and the handshake would fail.

        PeerStore.ClearRemoteTrust( "Test/$M14ClearPeer" );
        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        await using var sender = await CreateSenderAsync( "M14Clear", "$M14ClearPeer", peer.Address, token );

        var f = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var settings = sender.GetRequiredFeature<TransportManagerFeature>();
        settings.StableConnectionTime = TimeSpan.FromMilliseconds( 300 );

        // Three quick flaps.
        for( int i = 0; i < 3; ++i ) await AcceptNegotiateAndDropAsync( peer, peerKey, 0, token );
        await WaitForAsync( () => f.FlapCount >= 3, "the flap count to build up", token );

        // Now one that lasts longer than StableConnectionTime before dying.
        await AcceptNegotiateAndDropAsync( peer, peerKey, 500, token );

        await WaitForAsync( () => f.FlapCount == 1, "the flap count to reset", token );
        f.FlapCount.ShouldBe( 1,
            "A connection that lasted is evidence the remote is healthy: the history is forgotten and " +
            "this kill starts a fresh sequence, so the next retry is prompt again." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_peer_sending_an_impossible_downgrade_is_not_reported_as_our_fault_Async( CancellationToken token )
    {
        // Two findings meet here.
        //
        // A downgrade can only name a version below the current one. Reading it without checking lets
        // the value reach SendInitialMessageAsync and fail an ARGUMENT check from inside the connect
        // task, which surfaces as an unhandled error about this code — for something a peer did.
        //
        // And a fault the peer caused must not be logged as an Error with a stack: on this path a
        // remote can produce one per reconnection, which is a log-volume problem and puts routine
        // noise in the bucket an operator watches for real faults.
        PeerStore.ClearRemoteTrust( "Test/$M14DownPeer" );
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 2000 );
        await using var peer = new AdversarialPeer();
        await using var sender = await CreateSenderAsync( "M14Down", "$M14DownPeer", peer.Address, token );

        await using( var c = await peer.AcceptAsync( token ) )
        {
            await c.ReadInitialMessageAsync( token );
            // "Use version 7" — a version this side cannot possibly produce.
            await c.SendZeroFrameAsync( PeerMessages.Build( ( ref FastByteWriter w ) =>
            {
                w.WriteByte( PeerMessages.DNegoDowngradeProtocol );
                w.WriteSmallUInt32( 7 );
            }, signWith: null ), token );
        }

        // ExtractCurrentTexts DRAINS the collector, so accumulate: re-reading it in a poll loop
        // throws away everything logged before the poll that finally matches.
        var texts = new List<string>();
        var deadline = DateTime.UtcNow.AddSeconds( 20 );
        while( DateTime.UtcNow < deadline )
        {
            texts.AddRange( logs.ExtractCurrentTexts() );
            if( texts.Any( t => t.Contains( "failed the exchange" ) ) ) break;
            await Task.Delay( 50, token );
        }
        texts.AddRange( logs.ExtractCurrentTexts() );

        texts.ShouldContain( t => t.Contains( "failed the exchange" ),
            "The initiator must report the peer's impossible downgrade — silence would make the " +
            "assertion below pass for the wrong reason." );
        texts.ShouldNotContain( t => t.Contains( "Unhandled error while connecting" ),
            "That wording says the fault is ours. It is the peer's: it sent a version we cannot speak." );
    }

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token, int seconds = 30 )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( !condition() )
        {
            if( DateTime.UtcNow > deadline ) Throw.CKException( $"Timeout while waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }
}
