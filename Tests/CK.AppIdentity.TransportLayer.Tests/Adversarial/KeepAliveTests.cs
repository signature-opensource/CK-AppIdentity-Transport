using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M13: nothing ever noticed a connection that stopped answering.
/// <para>
/// The protocol has two halves and only the answering half is self-evident: the responder answers
/// <c>Empty</c> with <c>EmptyAck</c> and the acknowledgment is consumed so that <c>LastReceived</c>
/// moves. With nothing emitting the request, that machinery answers a question nobody asks,
/// <c>LastReceived</c> is a value nobody reads, and
/// <see cref="ConnectionAvailability.DangerZone"/> is a state nothing can reach.
/// </para>
/// <para>
/// So a connection that died without saying so — peer power loss, a NAT entry expiring, a cable —
/// stayed <see cref="ConnectionAvailability.Connected"/> for ever. Writes into a half-open socket
/// keep succeeding into the kernel buffer, so the send side never learns either.
/// </para>
/// </summary>
[TestFixture]
public class KeepAliveTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static void SetFastKeepAlive( ApplicationIdentityService s, int idleMs = 200, int intervalMs = 100, int count = 2 )
    {
        var f = s.GetRequiredFeature<TransportManagerFeature>();
        f.KeepAliveIdleTime = TimeSpan.FromMilliseconds( idleMs );
        f.KeepAliveProbeInterval = TimeSpan.FromMilliseconds( intervalMs );
        f.KeepAliveProbeCount = count;
    }

    Task<ApplicationIdentityService> CreateSenderAsync( string name, string remoteName, string address, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = remoteName;
            c["Parties:0:Address"] = address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token, int seconds = 30 )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( !condition() )
        {
            if( DateTime.UtcNow > deadline ) Throw.CKException( $"Timeout while waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }

    /// <summary>
    /// Takes one connection to a validated transport and then goes silent while holding the socket
    /// open — a half-open connection on demand, which is otherwise very hard to fake. The caller must
    /// keep the returned connection alive for as long as it wants the socket held.
    /// </summary>
    async Task<PeerConnection> AcceptThenGoSilentAsync( AdversarialPeer peer, PeerIdentity peerKey, CancellationToken token )
    {
        var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );
        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { peerKey } ), token );
        var final = await c.ReadFrameAsync( token );
        final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "The transport must become valid." );
        return c;
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_half_open_connection_is_detected_Async( CancellationToken token )
    {
        // The finding. The socket is open, the peer is gone, and nothing on this side is wrong: reads
        // never complete and writes still succeed. Only the absence of an answer gives it away.
        PeerStore.ClearRemoteTrust( "Test/$M13HalfPeer" );
        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        await using var sender = await CreateSenderAsync( "M13Half", "$M13HalfPeer", peer.Address, token );
        SetFastKeepAlive( sender );

        await using var c = await AcceptThenGoSilentAsync( peer, peerKey, token );

        var f = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await WaitForAsync( () => f.CurrentTransport != null, "the transport to go live", token );
        // Hold THE instance: the feature swaps its transport on reconnect, so re-reading the property
        // would go null for the wrong reason.
        var dying = f.CurrentTransport!;

        await WaitForAsync( () => dying.Lifetime.IsCancellationRequested,
                            "the half-open connection to be condemned", token, 20 );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_connection_that_answers_is_left_alone_Async( CancellationToken token )
    {
        // The test that catches an over-eager timeout, and the one that exercises the responder and
        // the acknowledgment for real. Two live peers, idle for many keep-alive periods, exchanging
        // nothing but probes: the connection must be exactly as alive at the end as at the start.
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M13Listen";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = "$M13Send";
        }, ConfigureFastClock, token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M13Send";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = "$M13Listen";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureFastClock, token: token );

        SetFastKeepAlive( listener, idleMs: 150, intervalMs: 100, count: 2 );
        SetFastKeepAlive( sender, idleMs: 150, intervalMs: 100, count: 2 );

        var sf = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var lf = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await sf.ReadyTask.WaitAsync( token );
        await lf.ReadyTask.WaitAsync( token );
        var senderTransport = sf.CurrentTransport;
        senderTransport.ShouldNotBeNull();

        // ~13 idle periods with no application traffic at all.
        await Task.Delay( 2000, token );

        senderTransport!.Lifetime.IsCancellationRequested.ShouldBeFalse(
            "An answered keep-alive must not kill anything. This is the same transport instance: a " +
            "reconnection would have replaced it." );
        sf.CurrentTransport.ShouldBeSameAs( senderTransport );
        sf.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
        lf.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
        sf.FlapCount.ShouldBe( 0, "Nothing died, so nothing counts as a flap." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task The_availability_passes_through_DangerZone_Async( CancellationToken token )
    {
        // Only something watching for silence can produce DangerZone: it means "still connected, no
        // longer answering". An application wants that warning before the connection is declared
        // dead, not only after.
        PeerStore.ClearRemoteTrust( "Test/$M13DangerPeer" );
        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        await using var sender = await CreateSenderAsync( "M13Danger", "$M13DangerPeer", peer.Address, token );
        SetFastKeepAlive( sender );

        var seen = new List<ConnectionAvailability>();
        sender.GetRequiredFeature<TransportManagerFeature>().ConnectionAvailabilityChanged.Sync
            += ( monitor, f ) => { lock( seen ) seen.Add( f.ConnectionAvailability ); };

        await using var c = await AcceptThenGoSilentAsync( peer, peerKey, token );

        await WaitForAsync( () => { lock( seen ) return seen.Contains( ConnectionAvailability.DangerZone ); },
                            "the availability to reach DangerZone", token, 20 );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Keep_alive_can_be_switched_off_Async( CancellationToken token )
    {
        // A deployment whose transport has its own liveness must be able to turn this off — and a
        // disabled keep-alive must not merely stop killing, it must stop probing.
        PeerStore.ClearRemoteTrust( "Test/$M13OffPeer" );
        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        await using var sender = await CreateSenderAsync( "M13Off", "$M13OffPeer", peer.Address, token );
        // Fast interval and count FIRST, then disable. Leaving them at their 5 s / 3 defaults would
        // make this test pass whether or not the disable is honoured, because nothing could have died
        // inside the window either way.
        SetFastKeepAlive( sender );
        var f = sender.GetRequiredFeature<TransportManagerFeature>();
        f.KeepAliveIdleTime = TimeSpan.Zero;

        await using var c = await AcceptThenGoSilentAsync( peer, peerKey, token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await WaitForAsync( () => feature.CurrentTransport != null, "the transport to go live", token );
        var transport = feature.CurrentTransport!;

        // Far longer than the 200/100/2 of the other tests would have taken to kill it.
        await Task.Delay( 2000, token );
        transport.Lifetime.IsCancellationRequested.ShouldBeFalse(
            "With keep-alive off, a silent peer is nobody's business: the connection stays up." );
    }
}
