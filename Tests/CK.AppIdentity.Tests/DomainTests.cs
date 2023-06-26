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
        public async Task with_groups_initialization()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( with_groups_initialization ) );
            await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["PartyName"] = "SaaS1";
                c["Remotes:0:DomainName"] = "AllInOneInc";
                c["Remotes:0:Remotes:0:PartyName"] = "ControlBox";
                c["Remotes:0:Remotes:1:PartyName"] = "Hall1Wall";
                c["Remotes:0:Remotes:2:PartyName"] = "Hall2Wall";
                c["Remotes:0:Remotes:3:PartyName"] = "Hall1Trolley";
                c["Remotes:0:Remotes:4:PartyName"] = "Hall2Trolley";
                c["Remotes:1:DomainName"] = "OpalCorp";
                c["Remotes:1:Remotes:0:PartyName"] = "ControlBox";
                c["Remotes:1:Remotes:1:PartyName"] = "MeasureStation";
            } );
            s.DomainName.Should().Be( "SaaSProduct" );
            s.EnvironmentName.Should().Be( "#Development" );
            s.PartyName.Should().Be( "$SaaS1" );
            s.Remotes.Should().HaveCount( 2 );
            // Gets the group by its Configuration's domain name (a RemoteGroup doesn't expose its Domain since this has no real semantics).
            var allInOne = s.Remotes.OfType<PartyGroup>().Single( r => r.Configuration.DomainName == "AllInOneInc" );
            allInOne.Configuration.EnvironmentName.Should().Be( "#Development" );
            allInOne.Remotes.Should().HaveCount( 5, "There are 5 agents in this group." );
            allInOne.Remotes.Cast<RemoteParty>().Should().AllSatisfy( r =>
            {
                new[] { "$ControlBox", "$Hall1Wall", "$Hall2Wall", "$Hall1Trolley", "$Hall2Trolley" }.Should().Contain( r.PartyName );
                r.DomainName.Should().Be( "AllInOneInc" );
                r.EnvironmentName.Should().Be( "#Development" );
            } );
            var opal = s.Remotes.OfType<PartyGroup>().Single( r => r.Configuration.DomainName == "OpalCorp" );
            opal.Remotes.Should().HaveCount( 2, "There are 2 agents in this domain." );
            opal.Remotes.Cast<RemoteParty>().Should().AllSatisfy( r =>
            {
                new[] { "$ControlBox", "$MeasureStation" }.Should().Contain( r.PartyName );
                r.DomainName.Should().Be( "OpalCorp" );
                r.EnvironmentName.Should().Be( "#Development" );
            } );
        }

        [Test]
        public void SaaS_with_multiple_tenant_domains()
        {

        }

    }
}
