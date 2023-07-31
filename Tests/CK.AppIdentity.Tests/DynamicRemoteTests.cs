using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
{
    [TestFixture]
    public class DynamicRemoteTests
    {
        [Test]
        public async Task creating_and_destroying_dynamic_remote_or_tenants_raise_AllPartyChanged_event_Async()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( creating_and_destroying_dynamic_remote_or_tenants_raise_AllPartyChanged_event_Async ) );
            await using ApplicationIdentityService s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "OneCS-SaaS/$OneCS1";
            } );
            var events = new List<string>();
            s.AllPartyChanged.Sync += ( m, r ) =>
            {
                bool appear = !r.IsDestroyed;
                string msg;
                if( appear )
                {
                    msg = $"'{r}' appeared.";
                    r.ApplicationIdentityService.AllParties.Should().Contain( r, msg );
                }
                else
                {
                    msg = $"'{r}' disappeared.";
                    r.ApplicationIdentityService.AllParties.Should().NotContain( r, msg );
                }
                m.Trace( msg );
                events.Add( msg );
            };
            Throw.DebugAssert( s != null );
            s.Parties.Should().BeEmpty();

            // Adding a simple remote. This is a RemoteParty.
            IReadOnlyCollection<IRemoteParty>? addedRemotes = await s.AddMultipleRemotesAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "LogTower";
            } );
            Throw.DebugAssert( addedRemotes != null );
            var logTower = addedRemotes.Single();
            logTower.DomainName.Should().Be( s.DomainName );
            logTower.EnvironmentName.Should().Be( s.EnvironmentName );
            logTower.PartyName.Should().Be( "$LogTower" );
            s.Parties.Single().Should().BeSameAs( logTower );
            logTower.IsDynamic.Should().BeTrue( "This remote is dynamic." );

            // Adding a tenant domain with an initial configured remote.
            AddedDynamicParties? added = await s.AddPartiesAsync( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "LaToulousaine";
                c["PartyName"] = "$LaToulousaine";
                c["EnvironmentName"] = "#Debug";
                c["Parties:0:PartyName"] = "SignatureBox";
            } );
            Throw.DebugAssert( added != null );
            var laToulousaine = added.Value.Tenants.Single();
            laToulousaine.IsDynamic.Should().BeTrue();
            var signatureBox = laToulousaine.Remotes.Single();
            signatureBox.FullName.Should().Be( "LaToulousaine/$SignatureBox/#Debug" );
            signatureBox.IsDynamic.Should().BeTrue( "The signatureBox has been dynamically added by its tenant." );

            // Adding a new dynamic remote to the domain.
            addedRemotes = await laToulousaine.AddMultipleRemotesAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "Trolley1";
            } );
            Throw.DebugAssert( addedRemotes != null );
            var theTrolley = addedRemotes.Single();
            theTrolley.FullName.Should().Be( "LaToulousaine/$Trolley1/#Debug" );
            theTrolley.IsDynamic.Should().BeTrue();
            laToulousaine.Remotes.Should().HaveCount( 2 );

            // Adding another new dynamic remote to a dynamic domain.
            addedRemotes = await laToulousaine.AddMultipleRemotesAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "Trolley2";
            } );
            Throw.DebugAssert( addedRemotes != null );
            var theTrolley2 = addedRemotes.Single();
            theTrolley2.FullName.Should().Be( "LaToulousaine/$Trolley2/#Debug" );
            theTrolley2.IsDynamic.Should().BeTrue();
            laToulousaine.Remotes.Should().HaveCount( 3 );

            // Destroying dynamic remotes.
            s.Parties.Should().HaveCount( 2, "The LogTower and the LaToulousaine." );
            logTower.IsDestroyed.Should().BeFalse();
            // The destruction is a background process that can be initiated by the
            // synchronous SetDestroyed().
            logTower.SetDestroyed();
            // To wait for the actual destruction of a remote, DestroyAsync() can always be called.
            await logTower.DestroyAsync();
            s.Parties.Should().HaveCount( 1, "LaToulousaine only." );
            // Even when it's done of course.
            await logTower.DestroyAsync();

            // Destroying the dynamic Trolley.
            await theTrolley.DestroyAsync();

            // Destroying the tenant domain "OneCS-SaaS/$LaToulousaine/#Debug"
            // with "LaToulousaine/$SignatureBox/#Debug" and "LaToulousaine/$Trolley2/#Debug" in it.
            await laToulousaine.DestroyAsync();
            s.Parties.Should().BeEmpty();

            events.Should().BeEquivalentTo( new string[]
            {
                "'OneCS-SaaS/$LogTower/#Development' appeared.",

                // A group appears and its initially defined
                // remotes also appear in the events (as if it was dynamically added):
                // the event unifies the behavior.
                "'LaToulousaine/$LaToulousaine/#Debug' appeared.",
                "'LaToulousaine/$SignatureBox/#Debug' appeared.",

                "'LaToulousaine/$Trolley1/#Debug' appeared.",
                "'LaToulousaine/$Trolley2/#Debug' appeared.",

                "'OneCS-SaaS/$LogTower/#Development' disappeared.",

                "'LaToulousaine/$Trolley1/#Debug' disappeared.",

                // When a group is destroyed, its destroyed remotes
                // appear before it.
                "'LaToulousaine/$SignatureBox/#Debug' disappeared.",
                "'LaToulousaine/$Trolley2/#Debug' disappeared.",
                "'LaToulousaine/$LaToulousaine/#Debug' disappeared."
            } );
        }
    }
}
