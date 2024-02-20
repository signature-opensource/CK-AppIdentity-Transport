using CK.AppIdentity.TransportLayer;
using CK.Core;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestPlatform.ObjectModel;
using NUnit.Framework;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{


    [TestFixture]
    public class ListenerPeeringIssuesTests
    {
        // Uses a 50ms instead of the default 1000ms for tests.
        SystemClockTester _systemClock = new SystemClockTester( 50 );

        void ConfigureClock( ServiceCollection services )
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        }

        [Test]
        [Timeout( 7000 )]
        public async Task UnknwonIncoming_to_InitiatorConflict_to_None_to_UntrustedIncoming_to_Accepted_Async()
        {
            TestHelper.GetCleanTestStoreFolder();

            TestHelper.Monitor.Info( "Creating empty Listener service (AlwaysListening)." );
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Listener";
                c["AllowFeatures"] = "BlobChannel";
                c["AlwaysListening"] = "true";
            } );

            var listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
            listenerTransport.GetPeeringIssues().Should().BeEmpty();
            listenerTransport.GetClonedPeeringIssues().Should().BeEmpty();
            var collector = new PeeringIssueCollector( listenerTransport, true );
            ApplicationIdentityService? sender = null;
            IRemoteParty? declaredRemote;
            try
            {
                using( var waiter = new PeeringIssueWaiter( listenerTransport ) )
                {
                    // Captures the (unresolved) next event task.
                    var nextEvent = waiter.NextEvent;

                    TestHelper.Monitor.Info( "Starts the sender: it is unknown for the listener. One UnknwonIncoming issue appears." );
                    // We need this remote to retry quickly, we use a heartbeat of 50 ms instead of 1000 ms.
                    // It will automatically trust the listener identity.
                    sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: ConfigureClock );
                    await sender.InitializationTask;

                    TestHelper.Monitor.Info( "Wait for the first UnknwonIncoming event." );
                    var theIssue = await nextEvent;
                    Throw.DebugAssert( theIssue != null );

                    TestHelper.Monitor.Info( "Check the exposed PeeringIssues and ClonedPeeringIssues and the first issue." );

                    listenerTransport.GetPeeringIssues().Should().Contain( theIssue );
                    var clonedIssues = listenerTransport.GetClonedPeeringIssues();
                    clonedIssues.Should().HaveCount( 1 );
                    clonedIssues[0].Should().Match<PeeringIssue>( i => i.IsClone )
                                            .And.NotBeSameAs( theIssue )
                                            .And.BeEquivalentTo( theIssue, o => o.Excluding( i => i.IsClone ) );

                    theIssue.IsListener.Should().BeTrue();
                    theIssue.IsInitiator.Should().BeFalse();
                    theIssue.Remote.Should().BeNull();
                    theIssue.Kind.Should().Be( PeeringIssueKind.UnknwonIncoming );
                    Throw.DebugAssert( theIssue.IncomingRequest != null );
                    theIssue.IncomingRequest.CurrentRemoteIdentity.Should().NotBeNull();
                    theIssue.IncomingRequest.FullName.Should().Be( "Test/$Sender/#Dev" );
                    theIssue.IncomingRequest.AvailableProtocols.Should().BeEquivalentTo( new[] { "Blob.0" } );
                    theIssue.IncomingRequest.ValidClockOffset.Should().BeTrue();

                    // Captures the (unresolved) next event task.
                    nextEvent = waiter.NextEvent;

                    TestHelper.Monitor.Info( "Declares the sender on the listener side but with a (bad) 'tcp:1.0.2.3' Address." );
                    declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
                    {
                        c["PartyName"] = "$Sender";
                        c["Address"] = "1.0.2.3";
                    } );
                    Throw.DebugAssert( declaredRemote != null );
                    // When the remote appears, the existing issue kind transitions from Unknwon to InitiatorConflict
                    // because the OnRemoteAppeared method check that the new remote has a TargetAddress (not waiting for
                    // the next incoming request).
                    // (This is the same object since we haven't clone the issue.)
                    var prevMessage = theIssue.IncomingRequest;
                    var theSameIssue = await nextEvent;
                    Throw.DebugAssert( theSameIssue == theIssue );
                    theIssue.Kind.Should().Be( PeeringIssueKind.InitiatorConflict );

                    TestHelper.Monitor.Info( "Wait for the remote's incoming connection." );
                    var alwaysTheSameIssue = await waiter.NextEvent;
                    Throw.DebugAssert( alwaysTheSameIssue == theIssue );
                    var butNotTheSameMessage = theIssue.IncomingRequest;
                    Throw.DebugAssert( butNotTheSameMessage != prevMessage );

                    TestHelper.Monitor.Info( "No change: still InitiatorConflict." );
                    theIssue.Kind.Should().Be( PeeringIssueKind.InitiatorConflict );

                    // Stop using the Waiter from now on.

                }

                TestHelper.Monitor.Info( "Destroys the remote Party with its buggy Address." );
                // The Party is destroyed: the PeeringIssue becomes "None" and is removed
                // from the list.
                await declaredRemote.DestroyAsync();
                TestHelper.Monitor.Info( "And recreates it as a listener." );
                declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
                {
                    c["PartyName"] = "$Sender";
                } );
                Throw.DebugAssert( declaredRemote != null );

                // The issue will become Untrusted: the remote now exists and no more InitiatorConflict.
                var transport = declaredRemote.GetFeature<TransportFeature>();
                Throw.DebugAssert( transport != null );

                using( TestHelper.Monitor.OpenInfo( "Let (at least) one incoming try reach us to be UntrustedIncoming." ) )
                {
                    PeeringIssue[] issues;
                    while( (issues = listenerTransport.GetPeeringIssues()).Length == 0 || issues[0].Kind != PeeringIssueKind.UntrustedIncoming );
                }
                // Accept the incoming remote.
                using( TestHelper.Monitor.OpenInfo( "Accept the incoming remote and wait for the Kind to become None: the connection is established" +
                                                    " (because the sender has its AutoTrustKey = \"Once\")." ) )
                {
                    var issues = listenerTransport.GetPeeringIssues();
                    issues.Should().HaveCount( 1 );
                    issues[0].Kind.Should().Be( PeeringIssueKind.UntrustedIncoming );
                    issues[0].CanAcceptRemoteIdentity.Should().BeTrue();

                    issues[0].AcceptRemoteIdentity( TestHelper.Monitor );
                    while( issues[0].Kind != PeeringIssueKind.None ) ;
                    // Also wait for the issues to be cleared (OnTransportAvailable).
                    while( listenerTransport.GetPeeringIssues().Length > 0 ) ;
                }
                var events = collector.StopAndGetEvents();
                events.Select( e => e.Kind ).Should().BeEquivalentTo( new[]
                {
                    // Initial state: the listener's remote is not declared.
                    PeeringIssueKind.UnknwonIncoming,
                    // The listener's remote is also an Initiator.
                    PeeringIssueKind.InitiatorConflict,
                    // The buggy listener's remote is removed.
                    PeeringIssueKind.None,
                    // The listener's remote is created.
                    PeeringIssueKind.UntrustedIncoming,
                    // The listener's remote is Accepted.
                    PeeringIssueKind.None
                } );
            }
            finally
            {
                if( sender != null ) await sender.DisposeAsync();
            }
        }


    }
}
