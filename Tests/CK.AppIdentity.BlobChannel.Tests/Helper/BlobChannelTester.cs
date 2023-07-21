using CK.AppIdentity.TransportLayer;
using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{

    public sealed class BlobChannelTester : IAsyncDisposable
    {
        readonly List<byte[]> _listenerReceived;
        readonly List<byte[]> _senderReceived;
        readonly ApplicationIdentityService _sender;
        readonly ApplicationIdentityService _listener;
        readonly TransportManagerFeature _senderTransport;
        readonly TransportManagerFeature _listenerTransport;
        readonly BlobChannelFeature _senderChannel;
        readonly BlobChannelFeature _listenerChannel;

        public TransportManagerFeature SenderTransport => _senderTransport;

        public ApplicationIdentityService.ISystemClock SenderClock => (ApplicationIdentityService.ISystemClock)_sender.SystemClock;

        public BlobChannelFeature SenderChannel => _senderChannel;

        public TransportManagerFeature ListenerTransport => _listenerTransport;

        public ApplicationIdentityService.ISystemClock ListenerClock => (ApplicationIdentityService.ISystemClock)_listener.SystemClock;

        public BlobChannelFeature ListenerChannel => _listenerChannel;

        public async Task CheckSendReceiveAsync()
        {
            await SendDataAsync( _listenerChannel );
            await SendDataAsync( _senderChannel );

            CheckDataReceived( _senderReceived );
            CheckDataReceived( _listenerReceived );
        }

        public async ValueTask DisposeAsync()
        {
            await _sender.DisposeAsync();
            await _listener.DisposeAsync();
        }

        BlobChannelTester( ApplicationIdentityService sender, ApplicationIdentityService listener )
        {
            _listenerReceived = new List<byte[]>();
            _senderReceived = new List<byte[]>();
            _sender = sender;
            _listener = listener;
            _senderTransport = sender.GetRequiredFeature<TransportManagerFeature>();
            _listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
            _senderChannel = SetupChannel( sender, _senderReceived );
            _listenerChannel = SetupChannel( listener, _listenerReceived );
        }

        public static async Task<BlobChannelTester> CreateTesterAsync( string autoTrustKey = "None",
                                                                       int heartbeatPeriod = 0,
                                                                       TimeSpan? senderOffset = null,
                                                                       TimeSpan? listenerOffset = null,
                                                                       NormalizedPath storeSubPath = default )
        {
            var sC = new SystemClockTester( heartbeatPeriod );
            if( senderOffset.HasValue ) sC.Offset = senderOffset.Value;
            var s = await CreateAndStartSenderAsync( autoTrustKey, storeSubPath, services => services.AddSingleton( sC ) );

            var lC = new SystemClockTester( heartbeatPeriod );
            if( listenerOffset.HasValue ) lC.Offset = listenerOffset.Value;
            var l = await CreateAndStartListenerAsync( autoTrustKey, storeSubPath, services => services.AddSingleton( lC ) );

            return new BlobChannelTester( s, l );
        }

        public static async Task<ApplicationIdentityService> CreateAndStartSenderAsync( string autoTrustKey = "None",
                                                                                        NormalizedPath storeSubPath = default,
                                                                                        Action<ServiceCollection>? configureServices = null )
        {
            return await TestHelper.CreateApplicationServiceAsync( c =>
            {
                if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
                c["AutoTrustKey"] = autoTrustKey;
                c["FullName"] = "Test/$Sender";
                c["Parties:0:PartyName"] = "$Listener";
                c["Parties:0:Address"] = "tcp:127.0.0.1";
                c["AllowFeatures"] = "BlobChannel";
            }, configureServices );
        }

        public static async Task<ApplicationIdentityService> CreateAndStartListenerAsync( string autoTrustKey = "None",
                                                                                          NormalizedPath storeSubPath = default,
                                                                                          Action<ServiceCollection>? configureServices = null )
        {
            return await TestHelper.CreateApplicationServiceAsync( c =>
            {
                if( !storeSubPath.IsEmptyPath ) c["RootStorePath"] = TestHelper.TestProjectFolder.Combine( storeSubPath );
                c["AutoTrustKey"] = autoTrustKey;
                c["FullName"] = "Test/$Listener";
                c["Parties:0:PartyName"] = "$Sender";
                c["AllowFeatures"] = "BlobChannel";
            }, configureServices );
        }

        public static BlobChannelFeature SetupChannel( ApplicationIdentityService from, List<byte[]> receivedData )
        {
            var channel = from.Remotes.Single().GetRequiredFeature<BlobChannelFeature>();
            channel.Received.Sync += ( monitor, sender, bytes ) =>
            {
                monitor.Info( $"{sender.Transport.Party.ApplicationIdentityService}: RECEIVED {bytes.Length} bytes." );
                receivedData.Add( bytes );
            };
            return channel;
        }

        public static async Task SendDataAsync( BlobChannelFeature c )
        {
            await c.Transport.ReadyTask;
            c.TrySend( new byte[] { 1 } ).Should().BeTrue();
            c.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
            c.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();
        }

        public static void CheckDataReceived( List<byte[]> received )
        {
            while( received.Count < 3 ) ;
            received[0].Should().BeEquivalentTo( new byte[] { 1 } );
            received[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
            received[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );
        }

    }
}
