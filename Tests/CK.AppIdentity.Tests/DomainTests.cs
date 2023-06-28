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
        public async Task with_tenant_domains_initialization()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( with_tenant_domains_initialization ) );
            await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "SaaSProduct";
                c["PartyName"] = "SaaS1";
                c["Parties:0:FullName"] = "AllInOneInc/$AllInOneInc";
                c["Parties:0:Parties:0:PartyName"] = "ControlBox";
                c["Parties:0:Parties:1:PartyName"] = "Hall1Wall";
                c["Parties:0:Parties:2:PartyName"] = "Hall2Wall";
                c["Parties:0:Parties:3:PartyName"] = "Hall1Trolley";
                c["Parties:0:Parties:4:PartyName"] = "Hall2Trolley";
                c["Parties:1:FullName"] = "OpalCorp/$OpalCorp";
                c["Parties:1:Parties:0:PartyName"] = "ControlBox";
                c["Parties:1:Parties:1:PartyName"] = "MeasureStation";
            } );
            s.DomainName.Should().Be( "SaaSProduct" );
            s.EnvironmentName.Should().Be( "#Development" );
            s.PartyName.Should().Be( "$SaaS1" );
            s.Parties.Should().HaveCount( 2 );

            var allInOne = s.TenantDomains.Single( d => d.PartyName == "$AllInOneInc" );
            allInOne.Configuration.EnvironmentName.Should().Be( "#Development" );
            allInOne.Remotes.Should().HaveCount( 5, "There are 5 agents in this group." );
            allInOne.Remotes.Should().AllSatisfy( r =>
            {
                new[] { "$ControlBox", "$Hall1Wall", "$Hall2Wall", "$Hall1Trolley", "$Hall2Trolley" }.Should().Contain( r.PartyName );
                r.DomainName.Should().Be( "AllInOneInc" );
                r.EnvironmentName.Should().Be( "#Development" );
            } );
            var opal = s.TenantDomains.Single( p => p.PartyName == "$OpalCorp" );
            opal.Remotes.Should().HaveCount( 2, "There are 2 agents in this domain." );
            opal.Remotes.Should().AllSatisfy( r =>
            {
                new[] { "$ControlBox", "$MeasureStation" }.Should().Contain( r.PartyName );
                r.DomainName.Should().Be( "OpalCorp" );
                r.EnvironmentName.Should().Be( "#Development" );
            } );
        }


        [Test]
        public async Task homonyms_are_disallowed_Parties_must_be_destroyed_before_being_added()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( homonyms_are_disallowed_Parties_must_be_destroyed_before_being_added ) );
            await using var s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "D/$P";
            } );
            s.AllParties.Should().HaveCount( 0 );

            // This is the Agent "D/$P".
            IOwnedParty? noWay = await s.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D/$P" );
            noWay.Should().BeNull();

            (await s.AddRemoteAsync( TestHelper.Monitor, s => s["PartyName"] = "$P1" )).Should().NotBeNull();

            noWay = await s.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D/$P" );
            noWay.Should().BeNull( "Adding a Party that is the application is not possible." );

            // Adding a Tenant D1.
            var d1 = await s.AddTenantDomainAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$D1" );
            Debug.Assert( d1 != null );

            noWay = await s.AddTenantDomainAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$D1" );
            noWay.Should().BeNull( "Duplicate tenant." );

            noWay = await d1.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D/$P" );
            noWay.Should().BeNull();

            var p1 = await d1.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$P1" );
            noWay.Should().BeNull( "Adding a Party that is the application is not possible (in the tenant)." );

            noWay = await d1.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$P1" );
            noWay.Should().BeNull( "Duplicate remote (in the defining tenant) is obviously not possible." );
            noWay = await s.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$P1" );
            noWay.Should().BeNull( "Duplicate remote (in the application) is not possible." );

            // Adding a Tenant D2.
            var d2 = await s.AddTenantDomainAsync( TestHelper.Monitor, s => s["FullName"] = "D2/$D2" );
            Debug.Assert( d2 != null );
            noWay = await d2.AddRemoteAsync( TestHelper.Monitor, s => s["FullName"] = "D1/$P1" );
            noWay.Should().BeNull( "Duplicate remote (from any other tenant) is not possible." );
        }


    }
}
