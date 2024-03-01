using CK.Core;
using CK.Monitoring;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Core.ActivityMonitor;
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


        [Test, CancelAfter( 7000 )]
        public async Task Switch_Off_On_and_Shutdown_Listener_Async( CancellationToken token )
        {
            TestHelper.Monitor.Info( "Creating Listener & Sender." );
            using var logCollector = GrandOutput.Default!.CreateMemoryCollector( 1000 );
            var listener = await TestHelper.CreateApplicationServiceAsync( c =>
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
            TestHelper.Monitor.Info( "Test: Switching Off the Listener." );
            listenerTransport.SwitchOff( "Testing OutgoingBackTask!" );
            // There is no "NotReadyTask". We just wait for the ConnectionAvailability to be updated.
            await Task.WhenAll( WaitForConnectionAvailabilityAsync( listenerTransport, ConnectionAvailability.None, token ),
                                WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.Low, token ) );

            var logs = logCollector.ExtractCurrentTexts();
            logs.Should().ContainInOrder(
                "Test: Switching Off the Listener.",
                "Switching remote 'Test/$Sender/#Dev' OFF: Switched off, Reason: 'Testing OutgoingBackTask!'.",
                "Received GoodbyeMessage from '[::ffff:127.0.0.1]:37120': Remote: Switched off, Reason: 'Testing OutgoingBackTask!'.",
                "Initiating reconnection attempt to 'TcpSocketTransportTypeService - 127.0.0.1:37120' for 'Test/$Listener/#Dev' in 5 seconds."
            );

            // Switch-on the listener.
            TestHelper.Monitor.Info( "Test: Switching Listener back On." );
            listenerTransport.SwitchOn();

            await Task.WhenAll( WaitForConnectionAvailabilityAsync( listenerTransport, ConnectionAvailability.Connected, token ),
                                WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.Connected, token ) );

            logs = logCollector.ExtractCurrentTexts();
            logs.Should().ContainInOrder(
                "Test: Switching Listener back On.",
                "Switching remote 'Test/$Sender/#Dev' ON.",
                "Received verified AcceptedProtocolsMessage message from 'Test/$Listener/#Dev'.",
                "Rebinding TransportController for 'Test/$Listener/#Dev'."
            );

            // Disposing the listener.
            TestHelper.Monitor.Info( "Test: Disposing the Listener." );
            await listener.DisposeAsync();

            await Task.WhenAll( WaitForConnectionAvailabilityAsync( listenerTransport, ConnectionAvailability.None, token ),
                                WaitForConnectionAvailabilityAsync( senderTransport, ConnectionAvailability.Low, token ) );

            logs = logCollector.ExtractCurrentTexts();
            logs.Should().ContainInOrder(
                "Test: Disposing the Listener.",
                "Stopping ApplicationIdentityService Agent for 'Application: Test/$Listener/#Dev'.",
                "Switching remote 'Test/$Sender/#Dev' OFF: Shutdown ApplicationIdentityService.",
                "Received GoodbyeMessage from '[::ffff:127.0.0.1]:37120': Remote: Shutdown ApplicationIdentityService.",
                "Initiating reconnection attempt to 'TcpSocketTransportTypeService - 127.0.0.1:37120' for 'Test/$Listener/#Dev' in 5 seconds."
            );

            static async Task WaitForConnectionAvailabilityAsync( TransportFeature t, ConnectionAvailability status, CancellationToken token )
            {
                while( t.ConnectionAvailability != status )
                {
                    await Task.Delay( 100, token );
                }
            }
        }

        [Test, CancelAfter( 7000 )]
        public async Task Initiator_alone_Async( CancellationToken token )
        {
            var sender = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "Test/$Sender";
                c["AutoTrustKey"] = "Once";
                c["Parties:0:PartyName"] = "$Listener";
                c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
            }, ConfigureFastClock, token: token );

            await Task.Delay( 5000, token );

            await sender.DisposeAsync();

            await Task.Delay( 1000, token );
        }

    }
}
