using CK.Core;
using FluentAssertions;
using NUnit.Framework;
using System;
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
        public async Task creating_and_destroying_dynamic_remote_Async()
        {
            using var gLog = TestHelper.Monitor.OpenInfo( nameof( creating_and_destroying_dynamic_remote_Async ) );
            await using ApplicationIdentityService s = await TestHelper.CreateApplicationServiceAsync( c =>
            {
                c["DomainName"] = "OneCS-SaaS";
                c["Local:Name"] = "OneCS1";
            } );
            Debug.Assert( s != null );
            s.Remotes.Should().BeEmpty();

            // Adding a simple remote.
            var simple = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "LogTower";
            } );
            Debug.Assert( simple != null );
            simple.DomainName.Should().Be( s.DomainName );
            simple.EnvironmentName.Should().Be( s.EnvironmentName );
            simple.Name.Should().Be( "LogTower" );
            s.Remotes.Single().Should().BeSameAs( simple );
            simple.IsRooted.Should().BeTrue( "This remote is in the root ApplicationIdentityService." );
            simple.IsDynamic.Should().BeTrue( "This remote is dynamic." );

            // Adding a remote that is a domain with an initial configured remote.
            var domain = await s.AddDynamicRemoteAsync( TestHelper.Monitor, c =>
            {
                c["Name"] = "LaToulousaine";
                c["EnvironmentName"] = "Debug";
                c["Domain:Remotes:0:Name"] = "SignatureBox";
            } );
            Debug.Assert( domain != null );
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

            // Destroying dynamic remotes.
            s.Remotes.Should().HaveCount( 2, "The LogTower and the LaToulousaine." );
            simple.IsDestroyed.Should().BeFalse();
            // The destruction is a background process that can be initiated by the
            // synchronous SetDestroyed().
            simple.SetDestroyed();
            // To wait for the actual destruction of a remote, DestroyAsync() can always be called.
            await simple.DestroyAsync();
            s.Remotes.Should().HaveCount( 1, "LaToulousaine only." );

            await simple.DestroyAsync();

            // Destroying the domain.
            await domain.DestroyAsync();
            s.Remotes.Should().BeEmpty();
        }
    }
}
