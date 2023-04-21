using CK.Core;
using CK.Monitoring;
using FluentAssertions;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{
    [TestFixture]
    public class BasicExchangeTests
    {
        [TestCase( "Reverted" )]
        [TestCase( "Regular" )]
        public async Task Listener_then_Sender_setup_Async( string mode )
        {
            bool regular = mode == "Regular";
            ApplicationIdentityService listener;
            ApplicationIdentityService sender;

            if( regular )
            {
                listener = await CreateAndStartListenerAsync();
                sender = await CreateAndStartSenderAsync();
            }
            else
            {
                sender = await CreateAndStartSenderAsync();
                listener = await CreateAndStartListenerAsync();
            }

            var listenerReceived = new List<byte[]>();
            var senderReceived = new List<byte[]>();
            BlobChannelFeature senderChannel;
            BlobChannelFeature listenerChannel;

            if( regular )
            {
                listenerChannel = SetupChannel( listener, sender, listenerReceived );
                senderChannel = SetupChannel( sender, listener, senderReceived );

                await SendDataAsync( listenerChannel );
                await SendDataAsync( senderChannel );

                CheckDataReceived( senderReceived );
                CheckDataReceived( listenerReceived );
            }
            else
            {
                senderChannel = SetupChannel( sender, listener, senderReceived );
                listenerChannel = SetupChannel( listener, sender, listenerReceived );

                await SendDataAsync( senderChannel );
                await SendDataAsync( listenerChannel );

                CheckDataReceived( listenerReceived );
                CheckDataReceived( senderReceived );
            }

            if( regular )
            {
                await sender.DisposeAsync();
                await listener.DisposeAsync();
            }
            else
            {
                await listener.DisposeAsync();
                await sender.DisposeAsync();
            }

            static async Task<ApplicationIdentityService> CreateAndStartListenerAsync()
            {
                return await TestHelper.CreateApplicationServiceAsync( c =>
                {
                    c["DomainName"] = "Test";
                    c["Local:Name"] = "Listener";
                    c["Remotes:0:Name"] = "Sender";
                    c["AllowFeatures"] = "BlobChannel";
                } );
            }

            static async Task<ApplicationIdentityService> CreateAndStartSenderAsync()
            {
                return await TestHelper.CreateApplicationServiceAsync( c =>
                {
                    c["DomainName"] = "Test";
                    c["Local:Name"] = "Sender";
                    c["Remotes:0:Name"] = "Listener";
                    c["Remotes:0:Address"] = "tcp:127.0.0.1";
                    c["AllowFeatures"] = "BlobChannel";
                } );
            }

            static BlobChannelFeature SetupChannel( ApplicationIdentityService from, ApplicationIdentityService to, List<byte[]> receivedData )
            {
                var channel = from.Remotes.FindRequired( to.Local.Name ).GetRequiredFeature<BlobChannelFeature>();
                channel.Received.Sync += ( monitor, sender, bytes ) =>
                {
                    monitor.Info( $"{sender.Transport.Party.ApplicationIdentity}: RECEIVED {bytes.Length} bytes." );
                    receivedData.Add( bytes );
                };
                return channel;
            }

            static async Task SendDataAsync( BlobChannelFeature c )
            {
                await c.Transport.ReadyTask;
                c.TrySend( new byte[] { 1 } ).Should().BeTrue();
                c.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
                c.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();
            }

            static void CheckDataReceived( List<byte[]> senderReceived )
            {
                while( senderReceived.Count < 3 ) ;
                senderReceived[0].Should().BeEquivalentTo( new byte[] { 1 } );
                senderReceived[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
                senderReceived[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );
            }
        }

        [Test]
        public async Task demo_BlobChannel_is_an_optin_Feature_Async()
        {
            // BlobChannel is an opt-in feature: it must be explicitly allowed.
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Listener";
                c["Remotes:0:Name"] = "Sender";
                c["AllowFeatures"] = "BlobChannel";
            } );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "Sender";
                c["Remotes:0:Name"] = "Listener";
                c["Remotes:0:Address"] = "tcp:127.0.0.1";
                c["AllowFeatures"] = "BlobChannel";
            } );
            // Setup Listener.
            var listenerReceived = new List<byte[]>();
            var listenerChannel = listener.Remotes.FindRequired( sender.Local.Name ).GetRequiredFeature<BlobChannelFeature>();
            listenerChannel.Received.Sync += ( monitor, sender, bytes ) =>
            {
                monitor.Info( $"{sender.Transport.Party.ApplicationIdentity}: RECEIVED {bytes.Length} bytes." );
                sender.Should().BeSameAs( listenerChannel );
                listenerReceived.Add( bytes );
            };
            // Setup Sender.
            var senderReceived = new List<byte[]>();
            var senderChannel = sender.Remotes.FindRequired( listener.Local.Name ).GetRequiredFeature<BlobChannelFeature>();
            senderChannel.Received.Sync += ( monitor, sender, bytes ) =>
            {
                monitor.Info( $"{sender.Transport.Party.ApplicationIdentity}: RECEIVED {bytes.Length} bytes." );
                sender.Should().BeSameAs( senderChannel );
                senderReceived.Add( bytes );
            };
            // Listener => Sender.
            await listenerChannel.Transport.ReadyTask;
            listenerChannel.TrySend( new byte[] { 1 } ).Should().BeTrue();
            listenerChannel.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
            listenerChannel.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();

            // Sender => Listener.
            await senderChannel.Transport.ReadyTask;
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

            await sender.DisposeAsync();
            await listener.DisposeAsync();
        }

    }
}
