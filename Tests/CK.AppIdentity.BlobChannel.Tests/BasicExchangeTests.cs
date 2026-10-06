using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;

[TestFixture]
public class BasicExchangeTests
{
    SystemClockTester _systemClock = new SystemClockTester( 50 );

    void AddFastClock( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
    }

    void AddFastClockAndBlobChannel( ServiceCollection services )
    {
        AddFastClock( services );
        services.AddSingleton<BlobChannelFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<BlobChannelFeatureDriver>() );
    }


    [Test]
    // A hang guard, not a performance check: this may be the first test of the process that pays the cold start
    // (JIT, DataProtection, X509) and ckli builds run tests of other repositories in parallel.
    [CancelAfter( 30000 )]
    public async Task demo_BlobChannel_is_an_optin_Feature_Async( CancellationToken token )
    {
        TestHelper.CleanupFolder( ApplicationIdentityServiceConfiguration.DefaultStoreRootPath );

        // BlobChannel is an opt-in feature: it must be explicitly allowed.
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Listener";
            c["Parties:0:PartyName"] = "Sender";
            c["AllowFeatures"] = "BlobChannel";
        }, AddFastClockAndBlobChannel, token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Sender";
            c["Parties:0:PartyName"] = "Listener";
            c["Parties:0:Address"] = "tcp:127.0.0.1";
            c["AllowFeatures"] = "BlobChannel";
        }, AddFastClockAndBlobChannel, token );
        var listenerChannel = listener.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();
        var senderChannel = sender.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();

        // We need to configure the keys otherwise the parties won't accept to talk to each other.
        // Each side pins the head of the other's key event log, as an operator would.
        listenerChannel.Transport.RemoteKeys.SetTrustedIdentity( TestHelper.Monitor, senderChannel.Transport.RemoteKeys.LocalKeys.State.Head );
        senderChannel.Transport.RemoteKeys.SetTrustedIdentity( TestHelper.Monitor, listenerChannel.Transport.RemoteKeys.LocalKeys.State.Head );

        // Setup Listener reception.
        var listenerReceived = new List<byte[]>();
        listenerChannel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            sender.ShouldBeSameAs( listenerChannel );
            lock( listenerReceived ) listenerReceived.Add( bytes );
        };
        // Setup Sender reception.
        var senderReceived = new List<byte[]>();
        senderChannel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            sender.ShouldBeSameAs( senderChannel );
            lock( senderReceived ) senderReceived.Add( bytes );
        };
        // Listener => Sender.
        // Before sending, ReadyTask can be awaited.
        await listenerChannel.Transport.ReadyTask.WaitAsync( token );
        listenerChannel.TrySend( [1] ).ShouldBeTrue();
        listenerChannel.TrySend( [1, 2] ).ShouldBeTrue();
        listenerChannel.TrySend( [1, 2, 3] ).ShouldBeTrue();

        // Sender => Listener.
        await senderChannel.Transport.ReadyTask.WaitAsync( token );
        senderChannel.TrySend( [1] ).ShouldBeTrue();
        senderChannel.TrySend( [1, 2] ).ShouldBeTrue();
        senderChannel.TrySend( [1, 2, 3] ).ShouldBeTrue();

        // Check data reception (this waits for the messages, cooperatively: the [CancelAfter] applies).
        await BlobChannelTester.CheckTestDataReceivedAsync( senderReceived, token );
        await BlobChannelTester.CheckTestDataReceivedAsync( listenerReceived, token );

        await sender.DisposeAsync();
        await listener.DisposeAsync();
    }

    [TestCase( "Reverted" )]
    [TestCase( "Regular" )]
    [CancelAfter( 30000 )]
    public async Task Listener_then_Sender_setup_using_AutoTrustKey_Once_Async( string mode, CancellationToken token )
    {
        TestHelper.CleanupFolder( ApplicationIdentityServiceConfiguration.DefaultStoreRootPath );

        bool regular = mode == "Regular";
        ApplicationIdentityService? listener = null;
        ApplicationIdentityService? sender = null;
        try
        {
            if( regular )
            {
                listener = await BlobChannelTester.CreateAndStartListenerAsync( autoTrustKey: "Once", configureServices: AddFastClock, token: token );
                sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: AddFastClock, token: token );
            }
            else
            {
                sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: AddFastClock, token: token );
                listener = await BlobChannelTester.CreateAndStartListenerAsync( autoTrustKey: "Once", configureServices: AddFastClock, token: token );
            }

            var listenerReceived = new List<byte[]>();
            var senderReceived = new List<byte[]>();
            BlobChannelFeature senderChannel;
            BlobChannelFeature listenerChannel;

            if( regular )
            {
                listenerChannel = BlobChannelTester.SetupChannel( listener, listenerReceived );
                senderChannel = BlobChannelTester.SetupChannel( sender, senderReceived );

                await BlobChannelTester.SendTestDataAsync( listenerChannel, token );
                await BlobChannelTester.SendTestDataAsync( senderChannel, token );
                BlobChannelTester.SendTestData( listenerChannel );
                BlobChannelTester.SendTestData( senderChannel );

                // 2 rounds of 3 messages have been sent on each side.
                await BlobChannelTester.CheckTestDataReceivedAsync( senderReceived, token );
                await BlobChannelTester.CheckTestDataReceivedAsync( listenerReceived, token );
                await BlobChannelTester.CheckTestDataReceivedAsync( senderReceived, token, from: 3 );
                await BlobChannelTester.CheckTestDataReceivedAsync( listenerReceived, token, from: 3 );
            }
            else
            {
                senderChannel = BlobChannelTester.SetupChannel( sender, senderReceived );
                listenerChannel = BlobChannelTester.SetupChannel( listener, listenerReceived );

                await BlobChannelTester.SendTestDataAsync( senderChannel, token );
                await BlobChannelTester.SendTestDataAsync( listenerChannel, token );
                BlobChannelTester.SendTestData( senderChannel );
                BlobChannelTester.SendTestData( listenerChannel );

                // 2 rounds of 3 messages have been sent on each side.
                await BlobChannelTester.CheckTestDataReceivedAsync( listenerReceived, token );
                await BlobChannelTester.CheckTestDataReceivedAsync( senderReceived, token );
                await BlobChannelTester.CheckTestDataReceivedAsync( listenerReceived, token, from: 3 );
                await BlobChannelTester.CheckTestDataReceivedAsync( senderReceived, token, from: 3 );
            }
        }
        finally
        {
            if( regular )
            {
                if( sender != null ) await sender.DisposeAsync();
                if( listener != null ) await listener.DisposeAsync();
            }
            else
            {
                if( listener != null ) await listener.DisposeAsync();
                if( sender != null ) await sender.DisposeAsync();
            }
        }


    }

}
