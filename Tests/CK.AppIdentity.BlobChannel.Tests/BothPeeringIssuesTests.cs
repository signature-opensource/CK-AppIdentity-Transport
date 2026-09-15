using CK.AppIdentity.TransportLayer;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestPlatform.ObjectModel;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests;



[TestFixture]
public class BothPeeringIssuesTests
{
    // Uses a 50ms instead of the default 1000ms for tests.
    SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
    }


    [TestCase( true, true )]
    [TestCase( false, true )]
    [TestCase( true, false )]
    [TestCase( false, false )]
    [CancelAfter( 7000 )]
    public async Task MissingProtocols_Async( bool senderHasProtocol, bool switchOffListener, CancellationToken token )
    {
        DotNetEventSourceCollector.Enable( "System.Net.Sockets", System.Diagnostics.Tracing.EventLevel.Verbose );
        DotNetEventSourceCollector.Enable( "Private.InternalDiagnostics.System.Net.Sockets", System.Diagnostics.Tracing.EventLevel.Verbose );
        using var autoDisable = Util.CreateDisposableAction( () =>
        {
            DotNetEventSourceCollector.Disable( "System.Net.Sockets" );
            DotNetEventSourceCollector.Disable( "Private.InternalDiagnostics.System.Net.Sockets" );
        } );


        TestHelper.GetCleanTestStoreFolder();

        TestHelper.Monitor.Info( "Tests: Creating Listener & Sender." );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Listener";

        }, ConfigureFastClock, token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = "Test/$Sender", ConfigureFastClock, token: token );

        var senderTransportManager = sender.GetRequiredFeature<TransportManagerFeature>();
        var senderIssues = new PeeringIssueCollector( senderTransportManager, skipSameKind: false );

        TestHelper.Monitor.Info( "Tests: Creates the sender Party (no AutoTrustKey)." );
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
        senderTransport.ReadyTask.Status.ShouldBe( TaskStatus.WaitingForActivation );

        var listenerTransportManager = listener.GetRequiredFeature<TransportManagerFeature>();
        var listenerIssues = new PeeringIssueCollector( listenerTransportManager, skipSameKind: false );

        TestHelper.Monitor.Info( "Tests: Creates the listener Party (no AutoTrustKey)." );
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


        if( switchOffListener )
        {
            TestHelper.Monitor.Info( "Tests: Switching off listener." );
            listenerTransport.SwitchOff( "Switching off listener!" );
            // A switched off listener preserves its issue if any.
            await listenerIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token );
        }
        else
        {
            TestHelper.Monitor.Info( "Tests: Destroying listener." );
            await listenerParty.DestroyAsync();
            // A destroyed listener mutates the issue to be an IncomingUnknwon.
            await listenerIssues.WaitForAsync( PeeringIssueKind.IncomingUnknwon, token );
        }

        // Obviously no change on the destroyed sender side.
        await senderIssues.WaitForAsync( PeeringIssueKind.None, token );

        if( switchOffListener )
        {
            TestHelper.Monitor.Info( "Tests: Switching listener back on." );
            listenerTransport.SwitchOn().ShouldBeTrue();
        }
        else
        {
            TestHelper.Monitor.Info( "Tests: Recreating the listener (still no AutoTrustKey but we know each other now)." );
            listenerParty = await listener.AddRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "$Sender";
                if( !senderHasProtocol ) c["AllowFeatures"] = "BlobChannel";
            } );
            Throw.DebugAssert( listenerParty != null );
            listenerTransport = listenerParty.GetFeature<TransportFeature>();
            Throw.DebugAssert( listenerTransport != null );
        }

        TestHelper.Monitor.Info( "Tests: Recreating the sender Party (still no AutoTrustKey but we know each other now)." );
        senderParty = await sender.AddRemoteAsync( TestHelper.Monitor, c =>
        {
            c["PartyName"] = "$Listener";
            c["Address"] = "tcp:127.0.0.1";
            if( senderHasProtocol ) c["AllowFeatures"] = "BlobChannel";
        } );
        Throw.DebugAssert( senderParty != null );
        senderTransport = senderParty.GetFeature<TransportFeature>();
        Throw.DebugAssert( senderTransport != null );

        // Both are still MissingProtocols.
        await Task.WhenAll( listenerIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token ),
                            senderIssues.WaitForAsync( PeeringIssueKind.MissingProtocols, token ) );


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
