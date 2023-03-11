using CK.Testing;
using CK.Core;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using System.Threading.Tasks;
using System.IO;
using System.Linq;
using System.Diagnostics;
using CK.Monitoring;
using FluentAssertions;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Configuration;
using static CK.Testing.MonitorTestHelper;
using CK.Monitoring.Handlers;

namespace CK.AppIdentity.Configuration.Tests
{
    [TestFixture]
    public class ConfigurationTests
    {
        [Test]
        public void AppIdentityConfiguration_from_IHostEnvironment_and_IConfiguration_can_be_default()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( AppIdentityConfiguration_from_IHostEnvironment_and_IConfiguration_can_be_default ) );
            using var config = new ConfigurationManager();
            var hostEnv = new HostingEnvironment()
            {
                ApplicationName = "HostApp",
                EnvironmentName = "HostEnv",
            };
            var appIdentity = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, hostEnv, config.GetSection( "CK-AppIdentity" ) );
            Debug.Assert( appIdentity != null );
            appIdentity.DomainName.Should().Be( "Default" );
            appIdentity.EnvironmentName.Should().Be( "HostEnv" );
            appIdentity.Local.Name.Should().Be( "HostApp" );
            appIdentity.Remotes.Should().BeEmpty();
        }

        [Test]
        public void AppIdentityConfiguration_from_IHostEnvironment_and_IConfiguration()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( AppIdentityConfiguration_from_IHostEnvironment_and_IConfiguration ) );
            using var config = new ConfigurationManager();
            var hostEnv = new HostingEnvironment()
            {
                ApplicationName = "HostApp",
                EnvironmentName = "HostEnv",
            };
            config["CK-AppIdentity:DomainName"] = "OurDomain";
            config["CK-AppIdentity:EnvironmentName"] = "TestEnvironment";
            config["CK-AppIdentity:Local:Name"] = "MyApp";
            config["CK-AppIdentity:Remotes:0:Name"] = "Daddy";
            config["CK-AppIdentity:Remotes:0:Address"] = "http://x.x";
            var appIdentity = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, hostEnv, config.GetSection( "CK-AppIdentity" ) );
            Debug.Assert( appIdentity != null );

            appIdentity.DomainName.Should().Be( "OurDomain" );
            appIdentity.EnvironmentName.Should().Be( "TestEnvironment" );
            appIdentity.Local.Name.Should().Be( "MyApp" );
            appIdentity.Remotes.Should().HaveCount(1);
            var remote = appIdentity.Remotes.Single();
            remote.Name.Should().Be( "Daddy" );
            remote.Address.Should().Be( "http://x.x" );
            remote.DomainName.Should().Be( "OurDomain" );
            remote.EnvironmentName.Should().Be( "TestEnvironment" );
        }

        [Test]
        public async Task Host_configuration_Async()
        {
            // The CoreApplicationIdentity can be tested only once (since it cannot be reset).
            // Moreover, here, we sharing the GrandOutput.Default: building the host
            // reconfigures the GrandOutput.Default.
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( Host_configuration_Async ) );

            // Let the handlers initialize their output folders.
            await Task.Delay( 200 );

            // To keep the file layout with timed folders, we need to locate the right folders...
            var ckMonDir = Directory.EnumerateDirectories( TestHelper.LogFolder.AppendPart( "CKMon" ) ).MaxBy( s => Path.GetFileName( s ) );
            Debug.Assert( ckMonDir != null );
            var textDir = Directory.EnumerateDirectories( TestHelper.LogFolder.AppendPart( "Text" ) ).MaxBy( s => Path.GetFileName( s ) );
            Debug.Assert( textDir != null );

            var config = new DynamicConfigurationSource();
            config["CK-Monitoring:GrandOutput:Handlers:TextFile:Path"] = textDir;
            config["CK-Monitoring:GrandOutput:Handlers:BinaryFile:Path"] = ckMonDir;

            var hostBuilder = new HostBuilder()
                                .ConfigureAppConfiguration( ( hostingContext, c ) => c.Add( config ) )
                                .UseCKAppIdentity( contextDescriptor: "some context..." );
            TestHelper.Monitor.Info( "Building the host: this file is closed." );
            var host = hostBuilder.Build();

            Debug.Assert( GrandOutput.Default != null );
            GrandOutput.Default.IdentityCard.HasApplicationIdentity.Should().BeTrue( "IdentityCard received the CoreApplicationIdentity." );

            TestHelper.Monitor.Info( "A second test file has been created." );
            await host.StartAsync();
            TestHelper.Monitor.Info( "Stopping the host. And since it is the GrandOutput.Default, the host dispose it!" );
            await host.StopAsync();
            TestHelper.Monitor.CloseGroup( "Done! (but you'll never see this!)" );
            GrandOutput.Default.Should().BeNull();

            GrandOutput.EnsureActiveDefault( new GrandOutputConfiguration()
            {
                Handlers =
                {
                    new Monitoring.Handlers.TextFileConfiguration() { Path = textDir },
                    new Monitoring.Handlers.BinaryFileConfiguration() { Path = ckMonDir }
                }
            } );
            TestHelper.Monitor.Info( "Third file created since we have reconfigured the GrandOutput.Default." );
        }
    }
}
