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
