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
/// Channel code that throws must never escape into the transport machinery.
/// <para>
/// Each hook below used to be called unguarded. Depending on the call site, the throw killed a
/// healthy transport (and with it every other protocol on the connection), left a half-activated
/// zombie transport that nothing ever killed or reconnected, or stopped a loop over the channels
/// at the first failure.
/// </para>
/// </summary>
[TestFixture]
public class ChannelHookFailureTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

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

    Action<ServiceCollection> ConfigureServices( Action<CountingChannelFeatureDriver>? configureDriver )
    {
        return services =>
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
            services.AddSingleton( sp =>
            {
                var d = new CountingChannelFeatureDriver( sp.GetRequiredService<TransportFeatureDriver>() );
                configureDriver?.Invoke( d );
                return d;
            } );
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<CountingChannelFeatureDriver>() );
        };
    }

    async Task<Peers> CreatePeersAsync( string name,
                                        CancellationToken token,
                                        Action<CountingChannelFeatureDriver>? configureListener = null,
                                        Action<CountingChannelFeatureDriver>? configureSender = null )
    {
        var listenerName = $"${name}L";
        var senderName = $"${name}S";
        var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{listenerName}";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = senderName;
        }, ConfigureServices( configureListener ), token: token );

        var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{senderName}";
            c["AutoTrustKey"] = "Once";
            c["AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = listenerName;
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureServices( configureSender ), token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderTransport.ReadyTask.WaitAsync( TimeSpan.FromSeconds( 30 ), token );
        await listenerTransport.ReadyTask.WaitAsync( TimeSpan.FromSeconds( 30 ), token );

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
    public async Task A_throwing_ReceiveAsync_skips_the_message_without_killing_the_transport_Async( CancellationToken token )
    {
        // The message is already off the wire: a handler bug is not a transport fault. Killing the
        // transport would drop every other protocol, and a peer that resends the message after
        // reconnecting would kill it again.
        await using var p = await CreatePeersAsync( "ThrowRecv", token );
        var transport = p.SenderTransport.CurrentTransport;
        transport.ShouldNotBeNull();
        p.ListenerChannel.ThrowOnReceiveId = 2;

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 2 ).ShouldBeTrue();
        p.SenderChannel.TrySend( 3 ).ShouldBeTrue();

        await WaitForAsync( () => p.ListenerChannel.Received.Count == 2, "the 2 other messages to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1, 3] );
        transport.Lifetime.IsCancellationRequested.ShouldBeFalse( "The transport survived." );
        p.SenderTransport.CurrentTransport.ShouldBeSameAs( transport );
    }

    [Test, CancelAfter( 90000 )]
    public async Task A_throwing_CreateHandler_kills_the_transport_and_the_reconnection_succeeds_Async( CancellationToken token )
    {
        // Before the fix, the activation job threw after the controller was bound to the transport
        // but before its loops started. The MicroAgent only logged it: the transport was never
        // killed, never reconnected, and the ReadyTask never completed.
        await using var p = await CreatePeersAsync( "ThrowCreate", token, configureSender: d => d.CreateHandlerFailures = 1 );

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        await WaitForAsync( () => p.ListenerChannel.Received.Count == 1, "the message to arrive", token );
        p.ListenerChannel.Received.ShouldBe( [1] );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_throwing_OnCurrentHandlerChanged_neither_breaks_activation_nor_disconnection_Async( CancellationToken token )
    {
        // This is a notification: the handler has changed regardless. On activation the throw used
        // to abort it (the zombie transport above); on disconnection it stopped the notification of
        // the channels and left the connection availability stale.
        await using var p = await CreatePeersAsync( "ThrowChanged", token, configureSender: d => d.ThrowOnHandlerChanged = true );
        p.SenderChannel.HandlerChangedCount.ShouldBe( 1 );

        p.SenderChannel.TrySend( 1 ).ShouldBeTrue();
        await WaitForAsync( () => p.ListenerChannel.Received.Count == 1, "the message to arrive", token );

        p.SenderTransport.SwitchOff( "Testing a throwing OnCurrentHandlerChanged." );
        await WaitForAsync( () => p.SenderTransport.ConnectionAvailability == ConnectionAvailability.None,
                            "the sender to be disconnected", token );
        p.SenderChannel.HandlerChangedCount.ShouldBe( 2, "Connection lost has been notified." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_throwing_Teardown_does_not_prevent_the_other_channels_teardown_Async( CancellationToken token )
    {
        CountingChannelFeatureDriver? driver = null;
        var service = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$ThrowTeardown";
            c["AllowFeatures"] = "CountingChannel";
            c["Parties:0:PartyName"] = "$ThrowTeardownA";
            c["Parties:1:PartyName"] = "$ThrowTeardownB";
        }, ConfigureServices( d => { driver = d; d.ThrowOnTeardown = true; } ), token: token );
        CountingChannelFeature[] channels;
        try
        {
            channels = service.AllRemotes.Select( r => r.GetRequiredFeature<CountingChannelFeature>() ).ToArray();
            channels.Length.ShouldBe( 2 );
            driver.ShouldNotBeNull();
        }
        finally
        {
            await service.DisposeAsync();
        }
        channels.ShouldAllBe( c => c.TornDown, "Both channels have been torn down even if the first one threw." );
    }
}
