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
                c["DomainName"] = "OneCS-SaaS";
                c["Local:Name"] = "OneCS1";
            } );
            var events = new List<string>();
            s.RemotesChanged.Sync += ( m, r ) =>
            {
                bool appear = !r.IsDestroyed;
                string msg;
                if( appear )
                {
                    msg = $"'{r.FullName}' appeared.";
                    r.ApplicationIdentity.Remotes.Should().Contain( r, msg );
                }
                else
                {
                    msg = $"'{r.FullName}' disappeared.";
                    r.ApplicationIdentity.Remotes.Should().NotContain( r, msg );
                }
                m.Trace( msg );
                events.Add( msg );
            };
            Debug.Assert( s != null );
            s.Remotes.Should().BeEmpty();

            // Adding a simple remote.
            var logTower = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "LogTower";
            } );
            Debug.Assert( logTower != null );
            logTower.DomainName.Should().Be( s.DomainName );
            logTower.EnvironmentName.Should().Be( s.EnvironmentName );
            logTower.Name.Should().Be( "LogTower" );
            s.Remotes.Single().Should().BeSameAs( logTower );
            logTower.IsRooted.Should().BeTrue( "This remote is in the root ApplicationIdentityService." );
            logTower.IsDynamic.Should().BeTrue( "This remote is dynamic." );

            // Adding a remote that is a domain with an initial configured remote.
            var domain = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "LaToulousaine";
                c["EnvironmentName"] = "Debug";
                c["Domain:Remotes:0:Name"] = "SignatureBox";
            } );
            Debug.Assert( domain != null );
            domain.FullName.Should().Be( "OneCS-SaaS/Debug/LaToulousaine" );
            domain.IsDynamic.Should().BeTrue();
            domain.IsRooted.Should().BeTrue();
            // This remote has a non null DomainApplicationIdentity.
            var laToulousaine = domain.DomainApplicationIdentity;
            Debug.Assert( laToulousaine != null, "The remote hosts the domain." );
            // This new domain is in a "Debug" environment name.
            laToulousaine.EnvironmentName.Should().Be( "Debug" );
            var signatureBox = laToulousaine.Remotes.Single();
            signatureBox.FullName.Should().Be( "LaToulousaine/Debug/SignatureBox" );
            signatureBox.IsRooted.Should().BeFalse( "The signatureBox is not rooted: it belongs to a DomainApplicationIdentity." );
            signatureBox.IsDynamic.Should().BeFalse( "The signatureBox is configured: it is not dynamic." );
            FluentActions.Invoking( () => signatureBox.SetDestroyed() )
                .Should().Throw<InvalidOperationException>( "A non dynamic remote is NOT destroyable." );

            // Adding a new dynamic remote to a dynamic domain.
            var theTrolley = await laToulousaine.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "Trolley1";
            } );
            Debug.Assert( theTrolley != null );
            theTrolley.FullName.Should().Be( "LaToulousaine/Debug/Trolley1" );
            theTrolley.IsDynamic.Should().BeTrue();
            laToulousaine.Remotes.Should().HaveCount( 2 );

            // Adding another new dynamic remote to a dynamic domain.
            var theTrolley2 = await laToulousaine.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "Trolley2";
            } );
            Debug.Assert( theTrolley2 != null );
            theTrolley2.FullName.Should().Be( "LaToulousaine/Debug/Trolley2" );
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
            await domain.DestroyAsync();
            s.Remotes.Should().BeEmpty();

            events.Should().BeEquivalentTo( new string[]
            {
                "'OneCS-SaaS/Development/LogTower' appeared.",

                // A remote that defines a domain appears and its initially defined
                // remotes also appear in the events (as if it was dynamically added):
                // the event unifies the behavior.
                "'OneCS-SaaS/Debug/LaToulousaine' appeared.",
                "'LaToulousaine/Debug/SignatureBox' appeared.",

                "'LaToulousaine/Debug/Trolley1' appeared.",
                "'LaToulousaine/Debug/Trolley2' appeared.",

                "'OneCS-SaaS/Development/LogTower' disappeared.",

                "'LaToulousaine/Debug/Trolley1' disappeared.",

                // When a remote that defines a domain is destroyed, its destroyed remotes
                // appear before it.
                "'LaToulousaine/Debug/SignatureBox' disappeared.",
                "'LaToulousaine/Debug/Trolley2' disappeared.",
                "'OneCS-SaaS/Debug/LaToulousaine' disappeared."
            } );
        }
    }
}
