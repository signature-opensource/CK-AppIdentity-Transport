using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Monitoring;
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
/// The connection lifecycle of the transport runtime: lost connections on the listening side, switch off and on,
/// eviction, stuck send loops, the key events requests of a peer and the revocations of a tenant domain.
/// </summary>
[TestFixture]
public class TransportRuntimeTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<CountingChannelFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<CountingChannelFeatureDriver>() );
    }

    sealed class Peers : IAsyncDisposable
    {
        public required ApplicationIdentityService Listener { get; init; }
        public required ApplicationIdentityService Sender { get; init; }
        public required TransportFeature ListenerTransport { get; init; }
        public required TransportFeature SenderTransport { get; init; }
        public required CountingChannelFeature ListenerChannel { get; init; }
        public required CountingChannelFeature SenderChannel { get; init; }

        public async ValueTask DisposeAsync()
        {
            await Sender.DisposeAsync();
            await Listener.DisposeAsync();
        }
    }

    async Task<Peers> CreatePeersAsync( string name, CancellationToken token )
    {
        var listenerName = $"${name}L";
        var senderName = $"${name}S";
        var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{listenerName}";
            c["Defaults:AutoTrustKey"] = "Once";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = senderName;
        }, ConfigureServices, token: token );

        var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{senderName}";
            c["Defaults:AutoTrustKey"] = "Once";
            c["Defaults:AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = listenerName;
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureServices, token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderTransport.ReadyTask.WaitAsync( token );
        await listenerTransport.ReadyTask.WaitAsync( token );

        return new Peers
        {
            Listener = listener,
            Sender = sender,
            ListenerTransport = listenerTransport,
            SenderTransport = senderTransport,
            ListenerChannel = listener.AllRemotes.Single().GetRequiredFeature<CountingChannelFeature>(),
            SenderChannel = sender.AllRemotes.Single().GetRequiredFeature<CountingChannelFeature>()
        };
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

    [Test, CancelAfter( 60000 )]
    public async Task the_listening_side_loses_the_connection_when_the_remote_leaves_Async( CancellationToken token )
    {
        // TR-1: only the initiator lowered its availability when a transport died. The listener stayed Connected (and kept
        // the routes of the gone remote) until the remote came back.
        await using var p = await CreatePeersAsync( "TR1", token );
        p.ListenerTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
        p.ListenerChannel.TrySend( 1 ).ShouldBeTrue( "Connected: the channel has a current handler." );

        p.SenderTransport.SwitchOff( "TR1: the initiator leaves." );

        await WaitForAsync( () => p.ListenerTransport.ConnectionAvailability == ConnectionAvailability.None,
                            "the listener to see the connection lost", token, 10 );
        p.ListenerChannel.TrySend( 2 ).ShouldBeFalse( "The channel has lost its current handler." );

        // And it comes back.
        p.SenderTransport.SwitchOn();
        await WaitForAsync( () => p.ListenerTransport.ConnectionAvailability == ConnectionAvailability.Connected,
                            "the listener to be connected again", token );
    }

    [Test, CancelAfter( 60000 )]
    public async Task a_switched_off_remote_sends_again_after_SwitchOn_Async( CancellationToken token )
    {
        // TR-2: the channel handlers enqueued into the controller they were created with, closed by the switch off. After
        // SwitchOn, the reused handlers wrote into the closed queue: every send of the switched side failed forever.
        await using var p = await CreatePeersAsync( "TR2", token );

        p.SenderTransport.SwitchOff( "TR2: maintenance." );
        await WaitForAsync( () => p.SenderTransport.ConnectionAvailability == ConnectionAvailability.None, "the switch off", token );
        p.SenderChannel.TrySend( 1 ).ShouldBeFalse( "Off: no current handler." );

        p.SenderTransport.SwitchOn();
        await WaitForAsync( () => p.SenderTransport.ConnectionAvailability == ConnectionAvailability.Connected, "the reconnection", token );

        p.SenderChannel.TrySend( 2 ).ShouldBeTrue( "The switched side can send again." );
        await WaitForAsync( () => p.ListenerChannel.Received.Contains( 2 ), "the message to arrive", token );
    }

    [Test, CancelAfter( 60000 )]
    public async Task a_stuck_send_loop_does_not_block_the_switch_off_Async( CancellationToken token )
    {
        // TR-4: the TransportManager loop awaited the send loop of a condemned transport without bound, and the only
        // thing that unblocks a send stuck on a peer that doesn't read (the kill of the transport) was a job of that
        // same loop: one stuck socket froze every remote and the shutdown.
        await using var p = await CreatePeersAsync( "TR4", token );
        var stuck = p.SenderTransport.CurrentTransport.ShouldNotBeNull();

        // The send of message 1 only ends when the transport's Lifetime is signaled.
        p.SenderChannel.BlockToken = stuck.Lifetime;
        p.SenderChannel.BlockedId = 1;
        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.BlockEntered.Wait( 10_000, token ).ShouldBeTrue( "The send loop is stuck." );

        p.SenderTransport.SwitchOff( "TR4: switching off a stuck remote." );
        // The block lasts 30 seconds: the switch off ends long before.
        await WaitForAsync( () => stuck.Lifetime.IsCancellationRequested
                                  && p.SenderTransport.ConnectionAvailability == ConnectionAvailability.None,
                            "the stuck transport to be killed", token, 10 );
    }

    [Test, CancelAfter( 90000 )]
    public async Task the_connection_that_evicts_the_previous_one_survives_Async( CancellationToken token )
    {
        // TR-3: when the send loop of the evicted transport was still running, the kill was scheduled for the transport
        // that had just been rebound (the new one), not for the evicted one.
        await using var p = await CreatePeersAsync( "TR3", token );
        var evicted = p.ListenerTransport.CurrentTransport.ShouldNotBeNull();

        // The listener doesn't read anymore on this connection (its receive loop is blocked by message 7) and its send
        // loop is stuck (message 8): from its point of view, the connection is alive.
        p.ListenerChannel.ReceiveBlockToken = evicted.Lifetime;
        p.ListenerChannel.ReceiveBlockedId = 7;
        p.SenderChannel.TrySend( 7 ).ShouldBeTrue();
        p.ListenerChannel.ReceiveBlockEntered.Wait( 10_000, token ).ShouldBeTrue( "The listener's receive loop is blocked." );
        p.ListenerChannel.BlockToken = evicted.Lifetime;
        p.ListenerChannel.BlockedId = 8;
        p.ListenerChannel.TrySend( 8 ).ShouldBeTrue();
        p.ListenerChannel.BlockEntered.Wait( 10_000, token ).ShouldBeTrue( "The listener's send loop is stuck." );

        // The sender drops the connection (the listener doesn't read its Goodbye) and connects again: the new connection
        // evicts the previous one.
        var senderFirst = p.SenderTransport.CurrentTransport.ShouldNotBeNull();
        p.SenderTransport.SwitchOff( "TR3: reconnecting." );
        await WaitForAsync( () => senderFirst.Lifetime.IsCancellationRequested, "the sender's first transport to die", token );
        p.SenderTransport.SwitchOn();

        await WaitForAsync( () => p.ListenerTransport.CurrentTransport != evicted, "the eviction", token );
        var winner = p.ListenerTransport.CurrentTransport.ShouldNotBeNull();
        await WaitForAsync( () => evicted.Lifetime.IsCancellationRequested, "the evicted transport to be killed", token, 15 );

        // Message 8 was not sent on the evicted transport: it is sent on the new one.
        await WaitForAsync( () => p.SenderChannel.Received.Contains( 8 ), "the queued message to arrive", token );
        // A few heartbeats later, the connection that won is still there.
        await Task.Delay( 1000, token );
        winner.Lifetime.IsCancellationRequested.ShouldBeFalse( "The new connection must not be killed." );
        p.ListenerTransport.CurrentTransport.ShouldBeSameAs( winner );
        p.ListenerTransport.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
        p.SenderChannel.TrySend( 9 ).ShouldBeTrue();
        await WaitForAsync( () => p.ListenerChannel.Received.Contains( 9 ), "a message on the new connection", token );
    }

    [Test, CancelAfter( 60000 )]
    public async Task the_key_events_requests_of_a_peer_have_at_most_one_queued_answer_Async( CancellationToken token )
    {
        // TR-6: each key events request of the peer queued an answer in the unbounded high priority queue. A peer that
        // doesn't read its socket and streams requests grew it without limit.
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 5000 );
        await using var p = await CreatePeersAsync( "TR6", token );

        // The listener's send loop is stuck: the answers wait in its queue.
        using var release = new CancellationTokenSource();
        p.ListenerChannel.BlockToken = release.Token;
        p.ListenerChannel.BlockedId = 1;
        p.ListenerChannel.TrySend( 1 ).ShouldBeTrue();
        p.ListenerChannel.BlockEntered.Wait( 10_000, token ).ShouldBeTrue();

        for( int i = 0; i < 10; ++i )
        {
            await p.SenderTransport.RequestKeyEventsAsync( TimeSpan.FromMilliseconds( 1 ) );
        }
        // Message 2 follows the 10 requests on the connection: once received, the requests have been handled.
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();
        await WaitForAsync( () => p.ListenerChannel.Received.Contains( 2 ), "the requests to be handled", token );

        release.Cancel();
        // Message 3 follows the answers.
        p.ListenerChannel.TrySend( 3 ).ShouldBeTrue();
        await WaitForAsync( () => p.SenderChannel.Received.Contains( 3 ), "the answers to be sent", token );

        logs.UpdateCachedEntries();
        logs.CachedTexts.Count( l => l.Contains( "Received the key events of '" ) && l.Contains( "$TR6L" ) )
            .ShouldBe( 1, "One answer for the 10 requests received while it was waiting." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task channels_registered_out_of_the_protocol_name_order_connect_Async( CancellationToken token )
    {
        // TR-5: the listener built the protocol map in the registration order of the channels ("Counting" before
        // "Alpha" here), but the map must be sorted (and in the order of the channels): every incoming connection failed.
        void TwoChannels( ServiceCollection services )
        {
            services.AddSingleton<AlphaChannelFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<AlphaChannelFeatureDriver>() );
            ConfigureServices( services );
        }
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TR5L";
            c["Defaults:AutoTrustKey"] = "Once";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AllowFeatures"] = "CountingChannel,AlphaChannel";
            c["Parties:0:PartyName"] = "$TR5S";
        }, TwoChannels, token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TR5S";
            c["Defaults:AutoTrustKey"] = "Once";
            c["Defaults:AllowFeatures"] = "CountingChannel,AlphaChannel";
            c["Parties:0:PartyName"] = "$TR5L";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, TwoChannels, token: token );

        var listenerRemote = listener.AllRemotes.Single();
        var senderRemote = sender.AllRemotes.Single();
        listenerRemote.GetRequiredFeature<TransportFeature>().RegisteredProtocols.Select( p => p.Name )
                      .ShouldBe( ["Counting", "Alpha"], "Registered in this order." );
        listenerRemote.GetRequiredFeature<TransportFeature>().BestRegisteredProtocols.Select( p => p.Name )
                      .ShouldBe( ["Alpha", "Counting"], "The channels are in the order of the protocol map." );

        await senderRemote.GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
        await listenerRemote.GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );

        senderRemote.GetRequiredFeature<CountingChannelFeature>().TrySend( 1 ).ShouldBeTrue();
        senderRemote.GetRequiredFeature<AlphaChannelFeature>().TrySend().ShouldBeTrue();
        listenerRemote.GetRequiredFeature<CountingChannelFeature>().TrySend( 2 ).ShouldBeTrue();
        listenerRemote.GetRequiredFeature<AlphaChannelFeature>().TrySend().ShouldBeTrue();
        await WaitForAsync( () => listenerRemote.GetRequiredFeature<CountingChannelFeature>().Received.Contains( 1 )
                                  && listenerRemote.GetRequiredFeature<AlphaChannelFeature>().ReceivedCount == 1
                                  && senderRemote.GetRequiredFeature<CountingChannelFeature>().Received.Contains( 2 )
                                  && senderRemote.GetRequiredFeature<AlphaChannelFeature>().ReceivedCount == 1,
                            "each message on its channel", token );
    }
}
