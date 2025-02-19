using CK.AppIdentity.KeyManagement;
using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;

[TestFixture]
public class BasicExchangeTests
{
    [Test]
    // The timeout must be enough for back task to be checked and exceptions to be dumped.
    //[CancelAfter( 4000 )]
    public async Task demo_BlobChannel_is_an_optin_Feature_Async( CancellationToken token = default )
    {
        TestHelper.GetCleanTestStoreFolder();

        // BlobChannel is an opt-in feature: it must be explicitly allowed.
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Listener";
            c["Parties:0:PartyName"] = "Sender";
            c["AllowFeatures"] = "BlobChannel";
        }, token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Sender";
            c["Parties:0:PartyName"] = "Listener";
            c["Parties:0:Address"] = "tcp:127.0.0.1";
            c["AllowFeatures"] = "BlobChannel";
        }, token: token );
        var listenerChannel = listener.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();
        var senderChannel = sender.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();

        // We need to configure the keys otherwise the parties won't accept to talk to each other.
        var senderIdentity = new RemoteIdentityKey( senderChannel.Transport.RemoteKeys.LocalKeys.CurrentIdentity );
        listenerChannel.Transport.RemoteKeys.SetTrustedIdentity( TestHelper.Monitor, senderIdentity );

        var listenerIdentity = new RemoteIdentityKey( listenerChannel.Transport.RemoteKeys.LocalKeys.CurrentIdentity );
        senderChannel.Transport.RemoteKeys.SetTrustedIdentity( TestHelper.Monitor, listenerIdentity );

        // Setup Listener reception.
        var listenerReceived = new List<byte[]>();
        listenerChannel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            sender.Should().BeSameAs( listenerChannel );
            listenerReceived.Add( bytes );
        };
        // Setup Sender reception.
        var senderReceived = new List<byte[]>();
        senderChannel.Received.Sync += ( monitor, sender, bytes ) =>
        {
            monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
            sender.Should().BeSameAs( senderChannel );
            senderReceived.Add( bytes );
        };
        // Listener => Sender.
        // Before sending, ReadyTask can be awaited.
        await listenerChannel.Transport.ReadyTask.WaitAsync( token );
        listenerChannel.TrySend( new byte[] { 1 } ).Should().BeTrue();
        listenerChannel.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
        listenerChannel.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();

        // Sender => Listener.
        await senderChannel.Transport.ReadyTask.WaitAsync( token );
        senderChannel.TrySend( new byte[] { 1 } ).Should().BeTrue();
        senderChannel.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
        senderChannel.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();

        // Check data reception.
        while( senderReceived.Count < 3 ) ;
        senderReceived[0].Should().BeEquivalentTo( new byte[] { 1 } );
        senderReceived[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
        senderReceived[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );

        while( listenerReceived.Count < 3 ) ;
        listenerReceived[0].Should().BeEquivalentTo( new byte[] { 1 } );
        listenerReceived[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
        listenerReceived[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );

        await Task.Delay( 2000, token );

        await sender.DisposeAsync();
        await listener.DisposeAsync();
    }

    SystemClockTester _systemClock = new SystemClockTester( 50 );
    void ConfigureClock( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
    }

    [TestCase( "Reverted" )]
    [TestCase( "Regular" )]
    [CancelAfter( 4000 )]
    public async Task Listener_then_Sender_setup_using_AutoTrustKey_Once_Async( string mode, CancellationToken token )
    {
        TestHelper.GetCleanTestStoreFolder();

        bool regular = mode == "Regular";
        ApplicationIdentityService? listener = null;
        ApplicationIdentityService? sender = null;
        try
        {
            if( regular )
            {
                listener = await BlobChannelTester.CreateAndStartListenerAsync( autoTrustKey: "Once", configureServices: ConfigureClock, token: token );
                sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: ConfigureClock, token: token );
            }
            else
            {
                sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: ConfigureClock, token: token );
                listener = await BlobChannelTester.CreateAndStartListenerAsync( autoTrustKey: "Once", configureServices: ConfigureClock, token: token );
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

                BlobChannelTester.CheckTestDataReceived( senderReceived );
                BlobChannelTester.CheckTestDataReceived( listenerReceived );
                BlobChannelTester.CheckTestDataReceived( senderReceived );
                BlobChannelTester.CheckTestDataReceived( listenerReceived );
            }
            else
            {
                senderChannel = BlobChannelTester.SetupChannel( sender, senderReceived );
                listenerChannel = BlobChannelTester.SetupChannel( listener, listenerReceived );

                await BlobChannelTester.SendTestDataAsync( senderChannel, token );
                await BlobChannelTester.SendTestDataAsync( listenerChannel, token );
                BlobChannelTester.SendTestData( senderChannel );
                BlobChannelTester.SendTestData( listenerChannel );

                BlobChannelTester.CheckTestDataReceived( listenerReceived );
                BlobChannelTester.CheckTestDataReceived( senderReceived );
                BlobChannelTester.CheckTestDataReceived( listenerReceived );
                BlobChannelTester.CheckTestDataReceived( senderReceived );
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
