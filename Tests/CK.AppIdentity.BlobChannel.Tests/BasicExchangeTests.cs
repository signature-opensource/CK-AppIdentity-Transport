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
        [Test]
        public async Task BlobChannel_is_an_optin_Feature_Async()
        {
            // BlobChannel is an opt-in feature: it must be explicitly allowed.
            await using var app1 = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "App1";
                c["Remotes:0:Name"] = "App2";
                c["Remotes:0:Address"] = "tcp:127.0.0.1";
                c["AllowFeatures"] = "BlobChannel";
            } );
            await using var app2 = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "Test";
                c["Local:Name"] = "App2";
                c["Remotes:0:Name"] = "App1";
                c["AllowFeatures"] = "BlobChannel";
            } );
            // Setup App1.
            var r1 = new List<byte[]>();
            var b1 = app1.Remotes.FindRequired( app2.Local.Name ).GetRequiredFeature<BlobChannelFeature>();
            b1.Received.Sync += ( monitor, sender, bytes ) =>
            {
                monitor.Info( $"{sender.Transport.Party.ApplicationIdentity}: RECEIVED {bytes.Length} bytes." );
                sender.Should().BeSameAs( b1 );
                r1.Add( bytes );
            };
            // Setup App2.
            var r2 = new List<byte[]>();
            var b2 = app2.Remotes.FindRequired( app1.Local.Name ).GetRequiredFeature<BlobChannelFeature>();
            b2.Received.Sync += ( monitor, sender, bytes ) =>
            {
                monitor.Info( $"{sender.Transport.Party.ApplicationIdentity}: RECEIVED {bytes.Length} bytes." );
                sender.Should().BeSameAs( b2 );
                r2.Add( bytes );
            };
            // App1 => App2.
            await b1.Transport.ReadyTask;
            b1.TrySend( new byte[] { 1 } ).Should().BeTrue();
            b1.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
            b1.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();

            // App2 => App1.
            await b2.Transport.ReadyTask;
            b2.TrySend( new byte[] { 1 } ).Should().BeTrue();
            b2.TrySend( new byte[] { 1, 2 } ).Should().BeTrue();
            b2.TrySend( new byte[] { 1, 2, 3 } ).Should().BeTrue();

            // Check data reception.
            while( r2.Count < 3 ) ;
            r2[0].Should().BeEquivalentTo( new byte[] { 1 } );
            r2[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
            r2[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );

            while( r1.Count < 3 ) ;
            r1[0].Should().BeEquivalentTo( new byte[] { 1 } );
            r1[1].Should().BeEquivalentTo( new byte[] { 1, 2 } );
            r1[2].Should().BeEquivalentTo( new byte[] { 1, 2, 3 } );

            await app2.DisposeAsync();
            await app1.DisposeAsync();
        }

    }
}
