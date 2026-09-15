using CK.AppIdentity.TransportLayer;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;



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
    [CancelAfter( 7000 )]
    public async Task UnknwonIncoming_to_InitiatorConflict_to_None_to_UntrustedIncoming_to_Accepted_Async( CancellationToken token )
    {
        TestHelper.GetCleanTestStoreFolder();

        TestHelper.Monitor.Info( "Creating empty Listener service (AlwaysListening)." );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Listener";
            c["AllowFeatures"] = "BlobChannel";
            c["AlwaysListening"] = "true";
        }, token: token );

        var listenerTransport = listener.GetRequiredFeature<TransportManagerFeature>();
        listenerTransport.GetPeeringIssues().ShouldBeEmpty();
        listenerTransport.GetClonedPeeringIssues().ShouldBeEmpty();
        var collector = new PeeringIssueCollector( listenerTransport, true );
        ApplicationIdentityService? sender = null;
        IRemoteParty? declaredRemote;
        try
        {
            using( var waiter = new PeeringIssueWaiter( listenerTransport ) )
            {
                // Captures the (unresolved) next event task.
                var nextEvent = waiter.NextEvent;

                TestHelper.Monitor.Info( "Tests: Starts the sender. It is unknown for the listener. One UnknwonIncoming issue appears." );
                // We need this remote to retry quickly, we use a heartbeat of 50 ms instead of 1000 ms.
                // It will automatically trust the listener identity.
                sender = await BlobChannelTester.CreateAndStartSenderAsync( autoTrustKey: "Once", configureServices: ConfigureClock, token: token );

                TestHelper.Monitor.Info( "Tests: Wait for the first UnknwonIncoming event." );
                var theIssue = await nextEvent.WaitAsync( token );
                Throw.DebugAssert( theIssue != null );

                TestHelper.Monitor.Info( "Tests: Check the exposed PeeringIssues and ClonedPeeringIssues and the first issue." );

                listenerTransport.GetPeeringIssues().ShouldContain( theIssue );
                var clonedIssues = listenerTransport.GetClonedPeeringIssues();
                clonedIssues.Length.ShouldBe( 1 );
                // Everything properties should be equal except IsClone.
                clonedIssues[0].ShouldMatch( i => i.IsClone ).ShouldNotBeSameAs( theIssue );

                theIssue.IsListener.ShouldBeTrue();
                theIssue.IsInitiator.ShouldBeFalse();
                theIssue.Remote.ShouldBeNull();

                theIssue.Kind.ShouldBe( PeeringIssueKind.IncomingUnknwon );
                Throw.DebugAssert( theIssue.IncomingRequest != null );
                theIssue.IncomingRequest.CurrentRemoteIdentity.ShouldNotBeNull();
                theIssue.IncomingRequest.FullName.ShouldBe( "Test/$Sender/#Dev" );
                theIssue.IncomingRequest.AvailableProtocols.ShouldBe( ["Blob.0"] );
                theIssue.IncomingRequest.IsValidClockOffset.ShouldBeFalse( "Always false when IncomingUnknwon or IncomingDisallowedTransport." );

                // Captures the (unresolved) next event task.
                nextEvent = waiter.NextEvent;

                TestHelper.Monitor.Info( "Tests: Declares the sender on the listener side but with a (bad) 'tcp:1.0.2.3' Address." );
                declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
                {
                    c["PartyName"] = "$Sender";
                    c["Address"] = "1.0.2.3";
                } );
                Throw.DebugAssert( declaredRemote != null );
                // When the remote appears, the existing issue kind transitions from IncomingUnknwon to InitiatorConflict
                // because the OnRemoteAppeared method check that the new remote has a TargetAddress (without waiting for
                // the next incoming request).
                // (This is the same object since we haven't clone the issue.)
                var prevMessage = theIssue.IncomingRequest;
                var theSameIssue = await nextEvent.WaitAsync(token);
                Throw.DebugAssert( theSameIssue == theIssue );
                theIssue.Kind.ShouldBe( PeeringIssueKind.InitiatorConflict );

                TestHelper.Monitor.Info( "Tests: Wait for the remote's incoming connection." );
                var alwaysTheSameIssue = await waiter.NextEvent.WaitAsync( token );
                Throw.DebugAssert( alwaysTheSameIssue == theIssue );
                var butNotTheSameMessage = theIssue.IncomingRequest;
                Throw.DebugAssert( butNotTheSameMessage != prevMessage );

                TestHelper.Monitor.Info( "Tests: No change: still InitiatorConflict." );
                theIssue.Kind.ShouldBe( PeeringIssueKind.InitiatorConflict );

                // Stop using the Waiter from now on.

            }

            TestHelper.Monitor.Info( "Tests: Destroys the remote Party with its buggy Address." );
            // The Party is destroyed: the PeeringIssue becomes "None" and is removed
            // from the list.
            await declaredRemote.DestroyAsync();
            TestHelper.Monitor.Info( "Tests: And recreates it as a listener." );
            declaredRemote = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Sender";
            } );
            Throw.DebugAssert( declaredRemote != null );

            // The issue will become UntrustedIncoming: the remote now exists and no more InitiatorConflict.
            var transport = declaredRemote.GetFeature<TransportFeature>();
            Throw.DebugAssert( transport != null );

            using( TestHelper.Monitor.OpenInfo( "Tests: Let (at least) one incoming try reach us to be UntrustedIncoming." ) )
            {
                PeeringIssue[] issues;
                while( (issues = listenerTransport.GetPeeringIssues()).Length == 0 || issues[0].Kind != PeeringIssueKind.RequiresLocalApproval );
            }
            // Accept the incoming remote.
            using( TestHelper.Monitor.OpenInfo( "Tests: Accept the incoming remote and wait for the Kind to become None: the connection is established" +
                                                " (because the sender has its AutoTrustKey = \"Once\")." ) )
            {
                var issues = listenerTransport.GetPeeringIssues();
                issues.Length.ShouldBe( 1 );
                issues[0].Kind.ShouldBe( PeeringIssueKind.RequiresLocalApproval );
                issues[0].CanAcceptRemoteIdentity.ShouldBeTrue();

                issues[0].AcceptRemoteIdentity( TestHelper.Monitor );
                while( issues[0].Kind != PeeringIssueKind.None ) ;
                // Also wait for the issues to be cleared (OnTransportAvailable).
                while( listenerTransport.GetPeeringIssues().Length > 0 ) ;

                // Check that the connection is up and running.
                // We don't dispose the tester as it would dispose our sender and listener.
                var blobTester = new BlobChannelTester( sender, listener );
                await blobTester.CheckSendReceiveAsync( true, token );
                await blobTester.CheckSendReceiveAsync( false, token );
            }
            var events = collector.StopAndGetEvents();
            events.Select( e => e.Kind ).ShouldBe(
            [
                // Initial state: the listener's remote is not declared.
                PeeringIssueKind.IncomingUnknwon,
                // The listener's remote is also an Initiator.
                PeeringIssueKind.InitiatorConflict,
                // The buggy listener's remote is removed.
                PeeringIssueKind.None,
                // The listener's remote is created.
                PeeringIssueKind.RequiresLocalApproval,
                // The listener's remote is Accepted.
                PeeringIssueKind.None
            ] );
        }
        finally
        {
            if( sender != null )
            {
                TestHelper.Monitor.Info( "Disposing sender." );
                await sender.DisposeAsync();
            }
        }
        using( TestHelper.Monitor.OpenInfo( "Waiting 1 second for final logs." ) )
        {
            await Task.Delay( 1000, token );
        }
    }

}
