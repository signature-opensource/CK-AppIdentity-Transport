using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
{
    [TestFixture]
    public class ConfigurationTests
    {
        [Test]
        public void basic_agent_configuration()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( basic_agent_configuration ) );
            var config = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "LaToulousaine/France/Albi";
                c["PartyName"] = "SignatureBox";

                c["Remotes:0:DomainName"] = "Signature/SaaSCentral";
                c["Remotes:0:EnvironmentName"] = "#Prod";
                c["Remotes:0:PartyName"] = "LogTower";
                c["Remotes:0:Address"] = "148.54.11.18:3712";

                c["Remotes:1:FullName"] = "LaToulousaine/London/$TrolleyCentral";
                c["Remotes:2:PartyName"] = "Trolley1";
            } );
            Debug.Assert( config != null );

            config.FullName.Should().Be( "LaToulousaine/France/Albi/$SignatureBox/#Development" );
            config.DomainName.Should().Be( "LaToulousaine/France/Albi" );
            config.PartyName.Should().Be( "SignatureBox" );
            config.EnvironmentName.Should().Be( "#Development" );
            config.Local.FullName.Should().Be( "LaToulousaine/France/Albi/$Local/#Development" );

            config.Remotes.Should().HaveCount( 3 );

            var logTower = config.Remotes.Single( r => r.FullName == "Signature/SaaSCentral/$LogTower/#Prod" );
            Debug.Assert( logTower != null );
            logTower.DomainName.Should().Be( "Signature/SaaSCentral" );
            logTower.EnvironmentName.Should().Be( "#Prod" );
            logTower.As<RemotePartyConfiguration>().PartyName.Should().Be( "LogTower" );
            logTower.As<RemotePartyConfiguration>().Address.Should().Be( "148.54.11.18:3712" );

            var trolleyCentral = config.Remotes.Single( r => r.FullName == "LaToulousaine/London/$TrolleyCentral/#Development" );
            Debug.Assert( trolleyCentral != null );
            trolleyCentral.DomainName.Should().Be( "LaToulousaine/London" );
            trolleyCentral.EnvironmentName.Should().Be( "#Development" );
            trolleyCentral.As<RemotePartyConfiguration>().PartyName.Should().Be( "TrolleyCentral" );
            trolleyCentral.As<RemotePartyConfiguration>().Address.Should().BeNull();

            var trolley1 = config.Remotes.Single( r => r.FullName == "LaToulousaine/France/Albi/$Trolley1/#Development" );
            Debug.Assert( trolley1 != null );
            trolley1.DomainName.Should().Be( "LaToulousaine/France/Albi" );
            trolley1.EnvironmentName.Should().Be( "#Development" );
            trolley1.As<RemotePartyConfiguration>().PartyName.Should().Be( "Trolley1" );
            trolley1.As<RemotePartyConfiguration>().Address.Should().BeNull();
        }
    }
}
