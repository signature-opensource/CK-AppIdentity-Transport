using CK.AppIdentity.TransportLayer;
using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestPlatform.ObjectModel;
using NUnit.Framework;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{


    [TestFixture]
    public class BothPeeringIssuesTests
    {
        // Uses a 50ms instead of the default 1000ms for tests.
        SystemClockTester _systemClock = new SystemClockTester( 50 );

        void ConfigureFastClock( ServiceCollection services )
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        }


        [Test]
        //[CancelAfter( 7000 )]
        public async Task MissingProtocols_Async( CancellationToken token )
        {
            TestHelper.GetCleanTestStoreFolder();

            TestHelper.Monitor.Info( "Creating Listener & Sender." );
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$Listener", ConfigureFastClock, token: token );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$Sender", ConfigureFastClock, token: token );

            TestHelper.Monitor.Info( "Creates the sender Party (no protocol)." );
            var senderTransportManager = sender.GetRequiredFeature<TransportManagerFeature>();
            var senderPeeringIssues = new PeeringIssueCollector( senderTransportManager, skipSameKind: true );
            var senderParty = await sender.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Listener";
                c["Address"] = "tcp:127.0.0.1";
            } );
            Throw.DebugAssert( senderParty != null );
            var senderTransport = senderParty.GetFeature<TransportFeature>();
            Throw.DebugAssert( senderTransport != null );
            senderTransport.ConnectionAvailability.Should().Be( ConnectionAvailability.None, "ConnectionAvailability.None" );
            senderTransport.ReadyTask.Status.Should().Be( TaskStatus.WaitingForActivation, "ReadyTask is WaitingForActivation." );

            TestHelper.Monitor.Info( "Creates the listener Party (no protocol)." );
            var listenerTransportManager = listener.GetRequiredFeature<TransportManagerFeature>();
            var listenerPeeringIssues = new PeeringIssueCollector( listenerTransportManager, skipSameKind: true );
            var listenerParty = await listener.AddRemoteAsync( TestHelper.Monitor, c => c["PartyName"] = "$Sender" );
            Throw.DebugAssert( listenerParty != null );
            var listenerTransport = listenerParty.GetFeature<TransportFeature>();
            Throw.DebugAssert( listenerTransport != null );

            await Task.Delay( 800, token );

            TestHelper.Monitor.Info( "Collecting PeeringIssues." );
            var senderIssues = senderPeeringIssues.GetEventsAndClear();
            var listenerIssues = listenerPeeringIssues.GetEventsAndClear();

            senderIssues.Last().Should().Match<PeeringIssue>( i => i.Kind == PeeringIssueKind.RequiresBothApproval && i.CanAcceptRemoteIdentity );
            listenerIssues.Last().Should().Match<PeeringIssue>( i => i.Kind == PeeringIssueKind.RequiresBothApproval && i.CanAcceptRemoteIdentity );
            CheckNoConnection( senderTransport, listenerTransport );

            using( TestHelper.Monitor.OpenInfo( "Destroying sender." ) )
            {
                await senderParty.DestroyAsync();
                await Task.Delay( 250, token );
            }

            TestHelper.Monitor.Info( "Collecting PeeringIssues." );
            senderIssues = senderPeeringIssues.GetEventsAndClear();
            listenerIssues = listenerPeeringIssues.GetEventsAndClear();

            senderIssues.Should().HaveCount( 1 );
            senderIssues.Single().Kind.Should().Be( PeeringIssueKind.None, "When an initiator is destroyed, its issue becomes None." );
            listenerIssues.Should().BeEmpty();
            CheckNoConnection( senderTransport, listenerTransport );

            using( TestHelper.Monitor.OpenInfo( "Destroying listener." ) )
            {
                await listenerParty.DestroyAsync();
                await Task.Delay( 100, token );
            }

            TestHelper.Monitor.Info( "Collecting PeeringIssues." );
            senderIssues = senderPeeringIssues.GetEventsAndClear();
            listenerIssues = listenerPeeringIssues.GetEventsAndClear();
            senderIssues.Should().BeEmpty();
            listenerIssues.Single().Kind.Should().Be( PeeringIssueKind.IncomingUnknwon, "When a listener is destroyed, its issue becomes IncomingUnknwon." );

            using( TestHelper.Monitor.OpenInfo( "Recreating listener and sender." ) )
            {
                listenerParty = await listener.AddRemoteAsync( TestHelper.Monitor, c => c["PartyName"] = "$Sender" );
                senderParty = await sender.AddRemoteAsync( TestHelper.Monitor, c =>
                {
                    c["PartyName"] = "$Listener";
                    c["Address"] = "tcp:127.0.0.1";
                } );
                await Task.Delay( 7000, token );
            }

            TestHelper.Monitor.Info( "Collecting PeeringIssues." );
            senderIssues = senderPeeringIssues.GetEventsAndClear();
            listenerIssues = listenerPeeringIssues.GetEventsAndClear();
            //senderIssues.Should().HaveCount( 1 );
            //senderIssues.Last().Should().Match<PeeringIssue>( i => i.Kind == PeeringIssueKind.RequiresBothApproval && i.CanAcceptRemoteIdentity );
            //listenerIssues.Should().HaveCount( 1 );
            //listenerIssues.Last().Should().Match<PeeringIssue>( i => i.Kind == PeeringIssueKind.RequiresBothApproval && i.CanAcceptRemoteIdentity );
            CheckNoConnection( senderTransport, listenerTransport );

            static void CheckNoConnection( TransportFeature senderTransport, TransportFeature listenerTransport )
            {
                senderTransport.ConnectionAvailability.Should().Be( ConnectionAvailability.None, "ConnectionAvailability.Connected" );
                senderTransport.ReadyTask.Status.Should().Be( TaskStatus.WaitingForActivation, "ReadyTask is WaitingForActivation." );
                listenerTransport.ConnectionAvailability.Should().Be( ConnectionAvailability.None, "ConnectionAvailability.None" );
                listenerTransport.ReadyTask.Status.Should().Be( TaskStatus.WaitingForActivation, "ReadyTask is WaitingForActivation." );
            }
        }

    }
}
