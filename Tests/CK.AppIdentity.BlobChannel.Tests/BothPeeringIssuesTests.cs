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


        [TestCase( true )]
        [TestCase( false )]
        //[CancelAfter( 7000 )]
        public async Task MissingProtocols_Async( bool senderHasProtocol, CancellationToken token )
        {
            TestHelper.GetCleanTestStoreFolder();

            TestHelper.Monitor.Info( "Tests: Creating Listener & Sender." );
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$Listener", ConfigureFastClock, token: token );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$Sender", ConfigureFastClock, token: token );

            var senderTransportManager = sender.GetRequiredFeature<TransportManagerFeature>();
            var senderIssues = new PeeringIssueCollector( senderTransportManager, skipSameKind: false );

            TestHelper.Monitor.Info( "Tests: Creates the sender Party (no protocol, no AutoTrustKey)." );
            var senderParty = await sender.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Listener";
                c["Address"] = "tcp:127.0.0.1";
                if( senderHasProtocol ) c["AllowFeatures"] = "BlobChannel";
            } );
            Throw.DebugAssert( senderParty != null );
            var senderTransport = senderParty.GetFeature<TransportFeature>();
            Throw.DebugAssert( senderTransport != null );

            // An initiator that fails to connect has no associated PeeringIssue: it is simply
            // not connected.
            senderTransport.ReadyTask.Status.Should().Be( TaskStatus.WaitingForActivation );

            var listenerTransportManager = listener.GetRequiredFeature<TransportManagerFeature>();
            var listenerIssues = new PeeringIssueCollector( listenerTransportManager, skipSameKind: false );

            TestHelper.Monitor.Info( "Tests: Creates the listener Party (no protocol, no AutoTrustKey)." );
            var listenerParty = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Sender";
                if( !senderHasProtocol ) c["AllowFeatures"] = "BlobChannel";
            } );
            Throw.DebugAssert( listenerParty != null );
            var listenerTransport = listenerParty.GetFeature<TransportFeature>();
            Throw.DebugAssert( listenerTransport != null );

            // Both are RequiresBothApproval.
            await Task.WhenAll( listenerIssues.WaitForAsync( PeeringIssueKind.RequiresBothApproval, token ),
                                senderIssues.WaitForAsync( PeeringIssueKind.RequiresBothApproval, token ) );

            // Resolves approvals.
            await Task.WhenAll( WaitCanAcceptAndAndAcceptRemoteAsync( listenerTransportManager, token ),
                                WaitCanAcceptAndAndAcceptRemoteAsync( senderTransportManager, token ) );

            // Both are MissingProtocols.
            await Task.WhenAll( listenerIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token ),
                                senderIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token ) );

            TestHelper.Monitor.Info( "Tests: Destroying sender." );
            await senderParty.DestroyAsync();

            // Listener keeps it MissingProtocols issue (it has never be connected, it cannot have a GoodbyeMessage).
            await Task.WhenAll( listenerIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token ),
                                senderIssues.WaitForAsync( PeeringIssueKind.None, token ) );


            TestHelper.Monitor.Info( "Tests: Destroying listener." );
            await listenerParty.DestroyAsync();

            // A destroyed listener mutates the isse to be an IncomingUnknwon.
            await Task.WhenAll( listenerIssues.WaitForAsync( PeeringIssueKind.IncomingUnknwon, token ),
                                senderIssues.WaitForAsync( PeeringIssueKind.None, token ) );

            static async Task WaitCanAcceptAndAndAcceptRemoteAsync( TransportManagerFeature transportManager, CancellationToken token )
            {
                for( ; ; )
                {
                    var accept = transportManager.GetPeeringIssues().FirstOrDefault( i => i.CanAcceptRemoteIdentity );
                    if( accept != null )
                    {
                        accept.AcceptRemoteIdentity( TestHelper.Monitor );
                        return;
                    }
                    await Task.Delay( 50, token );
                }
            }
        }

    }
}
