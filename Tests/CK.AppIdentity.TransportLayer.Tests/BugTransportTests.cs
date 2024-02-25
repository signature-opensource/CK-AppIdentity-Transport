using CK.Core;
using CK.Monitoring;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests
{
    [TestFixture]
    public class BugTransportTests
    {
        // Uses a 50ms instead of the default 1000ms for tests.
        readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

        void ConfigureFastClock( ServiceCollection services )
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        }

        [CancelAfter( 10000 )]
        [TestCase( BugTransportTypeService.BugType.TransportCreate,
            "Error while creating Transport to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreate'. Retrying in 1 seconds." )]
        [TestCase( BugTransportTypeService.BugType.TransportCreateInline,
            "Error while creating Transport to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreateInline'. Retrying in 1 seconds." )]
        [TestCase( BugTransportTypeService.BugType.TransportCreateNull,
            "Unable to open connection to 'Test/$Other/#Dev' at 'BugTransportTypeService - TransportCreateNull'. Retrying in 1 seconds." )]
        [TestCase( BugTransportTypeService.BugType.TransportWrite,
            "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 2 second." )]
        [TestCase( BugTransportTypeService.BugType.TransportWriteInline,
            "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 2 second." )]
        [TestCase( BugTransportTypeService.BugType.TransportRead,
            "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 2 second." )]
        [TestCase( BugTransportTypeService.BugType.TransportReadInline,
            "Unhandled error while connecting to 'Test/$Other/#Dev'. Retrying in 2 second." )]
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

            Throw.DebugAssert( "CreateApplicationServiceAsync has used the TestHelper.Monitor.", GrandOutput.Default != null );
            using( var logCollector = GrandOutput.Default.CreateMemoryCollector( 1000 ) )
            {
                await Task.Delay( 1000, token );
                logCollector.UpdateCachedEntries();
                var logs = logCollector.CachedTexts;
                logs.Count( l => l.Contains( error ) ).Should().BeGreaterThan( 1 );
            }
        }

    }
}
