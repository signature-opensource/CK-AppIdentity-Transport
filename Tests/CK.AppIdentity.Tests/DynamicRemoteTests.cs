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
        public async Task creating_and_destroying_dynamic_remote_and_check_RemotesChanged_event_Async()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( creating_and_destroying_dynamic_remote_and_check_RemotesChanged_event_Async ) );
            await using ApplicationIdentityService s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["FullName"] = "OneCS-SaaS/$OneCS1";
            } );
            var events = new List<string>();
            s.RemotesChanged.Sync += ( m, r ) =>
            {
                bool appear = !r.IsDestroyed;
                string msg;
                if( appear )
                {
                    msg = $"'{r}' appeared.";
                    r.ApplicationIdentityService.AllRemotes.Should().Contain( r, msg );
                }
                else
                {
                    msg = $"'{r}' disappeared.";
                    r.ApplicationIdentityService.AllRemotes.Should().NotContain( r, msg );
                }
                m.Trace( msg );
                events.Add( msg );
            };
            Debug.Assert( s != null );
            s.Remotes.Should().BeEmpty();

            // Adding a simple remote. This is a RemoteParty.
            var logTower = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "LogTower";
            } ) as RemoteParty;
            Debug.Assert( logTower != null );
            logTower.DomainName.Should().Be( s.DomainName );
            logTower.EnvironmentName.Should().Be( s.EnvironmentName );
            logTower.PartyName.Should().Be( "$LogTower" );
            s.Remotes.Single().Should().BeSameAs( logTower );
            logTower.IsDynamic.Should().BeTrue( "This remote is dynamic." );

            // Adding a remote that is a group with an initial configured remote.
            var laToulousaine = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["DomainName"] = "LaToulousaine";
                c["EnvironmentName"] = "#Debug";
                c["Remotes:0:PartyName"] = "SignatureBox";
            } ) as PartyGroup;
            Debug.Assert( laToulousaine != null );
            laToulousaine.IsDynamic.Should().BeTrue();
            var signatureBox = (RemoteParty)laToulousaine.Remotes.Single();
            signatureBox.FullName.Should().Be( "LaToulousaine/$SignatureBox/#Debug" );
            signatureBox.IsDynamic.Should().BeFalse( "The signatureBox is configured: it is not dynamic." );
            FluentActions.Invoking( () => signatureBox.SetDestroyed() )
                .Should().Throw<InvalidOperationException>( "A non dynamic remote is NOT destroyable." );

            // Adding a new dynamic remote to a dynamic domain.
            var theTrolley = await laToulousaine.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "Trolley1";
            } ) as RemoteParty;
            Debug.Assert( theTrolley != null );
            theTrolley.FullName.Should().Be( "LaToulousaine/$Trolley1/#Debug" );
            theTrolley.IsDynamic.Should().BeTrue();
            laToulousaine.Remotes.Should().HaveCount( 2 );

            // Adding another new dynamic remote to a dynamic domain.
            var theTrolley2 = await laToulousaine.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["PartyName"] = "Trolley2";
            } ) as RemoteParty;
            Debug.Assert( theTrolley2 != null );
            theTrolley2.FullName.Should().Be( "LaToulousaine/$Trolley2/#Debug" );
            theTrolley2.IsDynamic.Should().BeTrue();
            laToulousaine.Remotes.Should().HaveCount( 3 );

            // Destroying dynamic remotes.
            s.Remotes.Should().HaveCount( 2, "The LogTower and the LaToulousaine." );
            logTower.IsDestroyed.Should().BeFalse();
            // The destruction is a background process that can be initiated by the
            // synchronous SetDestroyed().
            logTower.SetDestroyed();
            // To wait for the actual destruction of a remote, DestroyAsync() can always be called.
            await logTower.DestroyAsync();
            s.Remotes.Should().HaveCount( 1, "LaToulousaine only." );
            // Even when it's done of course.
            await logTower.DestroyAsync();

            // Destroying the dynamic Trolley.
            await theTrolley.DestroyAsync();

            // Destroying the remote "OneCS-SaaS/Debug/LaToulousaine" that defines a domain
            // with "LaToulousaine/Debug/SignatureBox" (static) and "LaToulousaine/Debug/Trolley2" (dynamic) in it.
            await laToulousaine.DestroyAsync();
            s.Remotes.Should().BeEmpty();

            events.Should().BeEquivalentTo( new string[]
            {
                "'OneCS-SaaS/$LogTower/#Development' appeared.",

                // A group appears and its initially defined
                // remotes also appear in the events (as if it was dynamically added):
                // the event unifies the behavior.
                "'Group 'LaToulousaine/#Debug'' appeared.",
                "'LaToulousaine/$SignatureBox/#Debug' appeared.",

                "'LaToulousaine/$Trolley1/#Debug' appeared.",
                "'LaToulousaine/$Trolley2/#Debug' appeared.",

                "'OneCS-SaaS/$LogTower/#Development' disappeared.",

                "'LaToulousaine/$Trolley1/#Debug' disappeared.",

                // When a group is destroyed, its destroyed remotes
                // appear before it.
                "'LaToulousaine/$SignatureBox/#Debug' disappeared.",
                "'LaToulousaine/$Trolley2/#Debug' disappeared.",
                "'Group 'LaToulousaine/#Debug'' disappeared."
            } );
        }
    }
}
