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
    public class TcpTransportTests
    {
        // Uses a 50ms instead of the default 1000ms for tests.
        readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

        void ConfigureFastClock( ServiceCollection services )
        {
            services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        }


        [CancelAfter( 100*10000 )]
        [Test]
        public async Task OutgoingBackTask_is_reused_to_monitor_reconnection_Async( CancellationToken token )
        {
            TestHelper.Monitor.Info( "Creating Listener & Sender." );
            using var logCollector = GrandOutput.Default!.CreateMemoryCollector( 1000 );
            await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Listener";
                c["AutoTrustKey"] = "Once";
                c["AlwaysListening"] = "True";
                c["Parties:0:PartyName"] = "$Sender";
            }, ConfigureFastClock, token: token );
            await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Sender";
                c["AutoTrustKey"] = "Once";
                c["Parties:0:PartyName"] = "$Listener";
                c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
            }, ConfigureFastClock, token: token );

            var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
            var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

            await senderTransport.ReadyTask.WaitAsync( token ).ConfigureAwait( false );
            await listenerTransport.ReadyTask.WaitAsync( token ).ConfigureAwait( false );

            senderTransport.ConnectionAvailability.Should().Be( ConnectionAvailability.Connected );
            listenerTransport.ConnectionAvailability.Should().Be( ConnectionAvailability.Connected );

            // Switch-off the listener.
            TestHelper.Monitor.Info( "Switching Off the Listener." );
            listenerTransport.SwitchOff( "Testing OutgoingBackTask!" );
            // There is no "NotReadyTask". We just wait for the ConnectionAvailability to be updated.
            await Task.WhenAll( WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.Connected, token ),
                                WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.Connected, token ) );

            var logs = logCollector.ExtractCurrentTexts();
            logs.Should().ContainInOrder( new[] {
                "Switching off remote 'Test/$Sender/#Dev' (reason: 'Testing OutgoingBackTask!').",
                "Received verified bye-bye message from 'Test/$Listener/#Dev': Testing OutgoingBackTask! (Shut up: 00:00:05)",
                "Initiating reconnection attempt to 'TcpSocketTransportTypeService - 127.0.0.1:37120' for 'Test/$Listener/#Dev' in 5 seconds.",
                ""
            } );

            // Switch-on the listener.
            TestHelper.Monitor.Info( "Switching Listener back On." );
            listenerTransport.SwitchOn();

            await Task.WhenAll( WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.None, token ),
                                WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.None, token ) );

            logCollector.ExtractCurrentTexts().Should().Contain( "Pouf" );

            static async Task WaitForConnectionAvailabilityAsync( TransportFeature t, ConnectionAvailability connected, CancellationToken token )
            {
                while( t.ConnectionAvailability == ConnectionAvailability.Connected )
                {
                    await Task.Delay( 100, token );
                }
            }
        }

    }
}
