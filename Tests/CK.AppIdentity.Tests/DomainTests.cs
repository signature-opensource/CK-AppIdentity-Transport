using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
{
    [TestFixture]
    public class DomainTests
    {
        [Test]
        public async Task Domain_initialization()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( Domain_initialization ) );
            await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["Local:Name"] = "SaaS1";
                c["Remotes:0:Name"] = "AllInOneInc";
                c["Remotes:0:Domain:Remotes:0:Name"] = "ControlBox";
                c["Remotes:0:Domain:Remotes:1:Name"] = "Hall1Wall";
                c["Remotes:0:Domain:Remotes:2:Name"] = "Hall2Wall";
                c["Remotes:0:Domain:Remotes:3:Name"] = "Hall1Trolley";
                c["Remotes:0:Domain:Remotes:4:Name"] = "Hall2Trolley";
                c["Remotes:1:Name"] = "OpalCorp";
                c["Remotes:1:Domain:Remotes:0:Name"] = "ControlBox";
                c["Remotes:1:Domain:Remotes:1:Name"] = "MeasureStation";
            } );
            s.DomainName.Should().Be( "SaaSProduct" );
            s.EnvironmentName.Should().Be( "Development" );
            s.Local.Name.Should().Be( "SaaS1" );
            s.Remotes.Should().HaveCount( 2 );
            var allInOne = s.Remotes.Single( r => r.Name == "AllInOneInc" );
            allInOne.DomainName.Should().Be( "SaaSProduct" );
            allInOne.EnvironmentName.Should().Be( "Development" );
            var dAllInOne = allInOne.DomainApplicationIdentity;
            Debug.Assert( dAllInOne != null );
            // A domain DomainName is the remote's name.
            // A domain Local name is the remote's name.
            // A domain EnvironmentName is the remote's EnvironmentName.
            dAllInOne.DomainName.Should().Be( "AllInOneInc" );
            dAllInOne.Local.Name.Should().Be( "AllInOneInc" );
            dAllInOne.EnvironmentName.Should().Be( "Development" );
            dAllInOne.Remotes.Should().HaveCount( 5, "There are 5 agents in this domain." );
            dAllInOne.Remotes.Should().AllSatisfy( r =>
            {
                new[] { "ControlBox", "Hall1Wall", "Hall2Wall", "Hall1Trolley", "Hall2Trolley" }.Should().Contain( r.Name );
                r.DomainName.Should().Be( "AllInOneInc" );
                r.EnvironmentName.Should().Be( "Development" );
            } );
            var opal = s.Remotes.Single( r => r.Name == "OpalCorp" );
            var dOpal = opal.DomainApplicationIdentity;
            Debug.Assert( dOpal != null );
            dOpal.Local.Name.Should().Be( "OpalCorp", "The 'domain controller'." );
            dOpal.Remotes.Should().HaveCount( 2, "There are 2 agents in this domain." );
            dOpal.Remotes.Should().AllSatisfy( r =>
            {
                new[] { "ControlBox", "MeasureStation" }.Should().Contain( r.Name );
                r.DomainName.Should().Be( "OpalCorp" );
                r.EnvironmentName.Should().Be( "Development" );
            } );
        }

        [Test]
        public void Domains_are_not_recursive()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( Domains_are_not_recursive ) );
            var good = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["Local:Name"] = "SaaS1";
                c["Remotes:0:Name"] = "AllInOneInc";
                c["Remotes:0:Domain:Remotes:0:Name"] = "ThisCannotBeASubDomain";
            } );
            good.Should().NotBeNull();
            using( TestHelper.Monitor.CollectTexts( out var logs ) )
            {
                var bad = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, c =>
                {
                    c["DomainName"] = "SaaSProduct";
                    c["Local:Name"] = "SaaS1";
                    c["Remotes:0:Name"] = "AllInOneInc";
                    c["Remotes:0:Domain:Remotes:0:Name"] = "ThisCannotBeASubDomain";
                    c["Remotes:0:Domain:Remotes:0:Domain:Something"] = "";
                } );
                bad.Should().BeNull();
                logs.Should().Contain( "Invalid configuration 'CK-AppIdentity:Remotes:0:Domain:Remotes:0:Domain': domains can only be defined in root Remotes." );
            }
        }

        [Test]
        public void Domains_Domain_LocalName_and_Environment_names_can_ONLY_be_the_Remote_ones()
        {
            var goodConfiguration = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["Local:Name"] = "SaaS1";
                c["Remotes:0:Name"] = "AllInOneInc";
                // A domain environment can be overridden: its remote, the "host" is by design
                // also in the given environment.
                c["Remotes:0:EnvironmentName"] = "SpecialEnvForDomain";
                c["Remotes:0:Domain:SomeKey"] = "This makes the Domain configuration section exists: the 'AllInOneInc' remote holds a Domain.";
                // This is useless... but this checked as soon as a "Domain" configuration key is here!
                c["Remotes:0:DomainName"] = "SaaSProduct";
                c["Remotes:0:Domain:DomainName"] = "AllInOneInc";
                c["Remotes:0:Domain:Local:Name"] = "AllInOneInc";
                c["Remotes:0:Domain:EnvironmentName"] = "SpecialEnvForDomain";
            } );
            Debug.Assert( goodConfiguration != null );
            var good = new ApplicationIdentityService( goodConfiguration, new SimpleServiceContainer() );
            var rAllInOne = good.Remotes.Single();
            rAllInOne.Name.Should().Be( "AllInOneInc" );
            rAllInOne.EnvironmentName.Should().Be( "SpecialEnvForDomain" );
            rAllInOne.DomainName.Should().Be( "SaaSProduct" );
            var dAllInOne = rAllInOne.DomainApplicationIdentity;
            Debug.Assert( dAllInOne != null );
            dAllInOne.DomainName.Should().Be( "AllInOneInc" );
            dAllInOne.EnvironmentName.Should().Be( "SpecialEnvForDomain" );
            dAllInOne.Local.Name.Should().Be( "AllInOneInc" );

            using( TestHelper.Monitor.CollectTexts( out var logs ) )
            {
                var bad = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, c =>
                {
                    c["DomainName"] = "SaaSProduct";
                    c["Local:Name"] = "SaaS1";
                    c["Remotes:0:Name"] = "AllInOneInc";
                    c["Remotes:0:EnvironmentName"] = "SpecialEnvForDomain";
                    c["Remotes:0:Domain:SomeKey"] = "This makes the Domain configuration section exists: the 'AllInOneInc' remote holds a Domain.";
                    // No way.
                    c["Remotes:0:DomainName"] = "ShouldBeSaaSProduct";
                    c["Remotes:0:Domain:DomainName"] = "ShouldBeAllInOneInc";
                    c["Remotes:0:Domain:Local:Name"] = "ShouldBeAllInOneInc";
                    c["Remotes:0:Domain:EnvironmentName"] = "ShouldBeSpecialEnvForDomain";
                } );
                bad.Should().BeNull();
                logs.Should().Contain( "Invalid 'CK-AppIdentity:Remotes:0:DomainName': it can only be the root application's domain 'SaaSProduct' (not 'ShouldBeSaaSProduct'). A remote that hosts a Domain MUST BE in the domain of the root application." )
                         .And.Contain( "Invalid 'CK-AppIdentity:Remotes:0:Domain:DomainName': it can only be the remote's name 'AllInOneInc' (not 'ShouldBeAllInOneInc')." )
                         .And.Contain( "Invalid 'CK-AppIdentity:Remotes:0:Domain:Local:Name': it can only be the remote's name 'AllInOneInc' (not 'ShouldBeAllInOneInc')." )
                         .And.Contain( "Invalid 'CK-AppIdentity:Remotes:0:Domain:EnvironmentName': it can only be remote's environment name 'SpecialEnvForDomain' (not 'ShouldBeSpecialEnvForDomain')." );
            }

        }
    }
}
