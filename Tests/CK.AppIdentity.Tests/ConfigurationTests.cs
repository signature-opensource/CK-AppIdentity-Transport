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
            config.PartyName.Should().Be( "$SignatureBox" );
            config.EnvironmentName.Should().Be( "#Development" );

            config.Remotes.Should().HaveCount( 3 );

            var logTower = config.Remotes.OfType<RemotePartyConfiguration>().Single( r => r.FullName == "Signature/SaaSCentral/$LogTower/#Prod" );
            logTower.DomainName.Should().Be( "Signature/SaaSCentral" );
            logTower.EnvironmentName.Should().Be( "#Prod" );
            logTower.As<RemotePartyConfiguration>().PartyName.Should().Be( "$LogTower" );
            logTower.As<RemotePartyConfiguration>().Address.Should().Be( "148.54.11.18:3712" );

            var trolleyCentral = config.Remotes.OfType<RemotePartyConfiguration>().Single( r => r.FullName == "LaToulousaine/London/$TrolleyCentral/#Development" );
            trolleyCentral.DomainName.Should().Be( "LaToulousaine/London" );
            trolleyCentral.EnvironmentName.Should().Be( "#Development" );
            trolleyCentral.As<RemotePartyConfiguration>().PartyName.Should().Be( "$TrolleyCentral" );
            trolleyCentral.As<RemotePartyConfiguration>().Address.Should().BeNull();

            var trolley1 = config.Remotes.OfType<RemotePartyConfiguration>().Single( r => r.FullName == "LaToulousaine/France/Albi/$Trolley1/#Development" );
            trolley1.DomainName.Should().Be( "LaToulousaine/France/Albi" );
            trolley1.EnvironmentName.Should().Be( "#Development" );
            trolley1.As<RemotePartyConfiguration>().PartyName.Should().Be( "$Trolley1" );
            trolley1.As<RemotePartyConfiguration>().Address.Should().BeNull();
        }

        [Test]
        public void groups_are_recursive()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( groups_are_recursive ) );
            var good = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["PartyName"] = "SaaS1";
                c["EnvironmentName"] = "#E";
                c["Remotes:0:DomainName"] = "D1";
                c["Remotes:0:Remotes:0:PartyName"] = "A1";
                c["Remotes:0:Remotes:1:DomainName"] = "D2";
                c["Remotes:0:Remotes:1:Remotes:0:PartyName"] = "A2";
            } );
            Debug.Assert( good != null );
            var g1 = good.Remotes.Cast<PartyGroupConfiguration>().Single();
            g1.Parties.Should().HaveCount( 2 );
            var a1 = g1.Parties.OfType<RemotePartyConfiguration>().Single();
            a1.FullName.Should().Be( "D1/$A1/#E" );
            var g2 = g1.Parties.OfType<PartyGroupConfiguration>().Single();
            var a2 = g2.Parties.OfType<RemotePartyConfiguration>().Single();
            a2.FullName.Should().Be( "D2/$A2/#E" );
        }


    }
}
