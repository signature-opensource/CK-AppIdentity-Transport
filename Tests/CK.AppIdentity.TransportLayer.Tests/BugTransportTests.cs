using CK.Core;
using CK.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class BugTransportTests
{
    // Uses a 50ms instead of the default 1000ms for tests.
    readonly SystemClockTester _systemClock = new SystemClockTester( 20 );

    void ConfigureFastClock( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
    }

    [CancelAfter( 5000 )]
    [TestCase( BugTransportTypeService.BugType.TransportCreate,
        "While creating Transport to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreate'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportCreateInline,
        "While creating Transport to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreateInline'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportCreateNull,
        "Unable to open connection to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreateNull'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportWrite,
        "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportWriteInline,
        "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportRead,
        "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 1 seconds." )]
    [TestCase( BugTransportTypeService.BugType.TransportReadInline,
        "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 1 seconds." )]
    public async Task OutgoingBackTask_never_stops_when_Transport_cannot_be_created_Async( BugTransportTypeService.BugType bugType,
                                                                                           string error,
                                                                                           CancellationToken token )
    {
        await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Sender";
            c["Parties:0:FullName"] = "Test/$Other";
            c["Parties:0:Address"] = "bug:" + bugType;
        }, ConfigureFastClock, token: token );
        var senderTransport = s.Remotes.Single().GetRequiredFeature<TransportFeature>();

        Throw.DebugAssert( "CreateApplicationServiceAsync has used the TestHelper.Monitor.", GrandOutput.Default != null );
        using var logCollector = GrandOutput.Default.CreateMemoryCollector( 1000 );

        await Task.Delay( 1300, token );
        TestHelper.Monitor.Info( "Tests: Switching off the sender." );
        senderTransport.SwitchOff( "Ending test." );
        //await Task.Delay( 5000, token );

        logCollector.UpdateCachedEntries();
        var logs = logCollector.CachedTexts;
        logs.Count( l => l.Contains( error ) ).ShouldBe( 1 );
        for( int i = 2; i < 4; i++ )
        {
            logs.Count( l => l.Contains( error.Replace( "in 1", $"in {i}" ) ) ).ShouldBe( 1, i.ToString() );
        }

        TestHelper.Monitor.Info( "Tests: Done." );
    }

}
