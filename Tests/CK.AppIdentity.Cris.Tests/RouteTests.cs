using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The routes of the parties (see <see cref="PartyRoute"/>): the transport layer computes them from the hosted routes and
/// the announcements of the connected remotes, and hosts the "Enlistment" route (the approval page of the System).
/// </summary>
[TestFixture]
public class RouteTests
{
    /// <summary>
    /// The listener's facts: a client application that is an approval page, and a hosted route whose target is a command name.
    /// </summary>
    public sealed class ApprovalPageFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public ApprovalPageFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
        {
            builder.AddClientApplication( new ClientApplicationDescription( "Admin",
                                                                            "/admin",
                                                                            ClientApplicationDescription.FactContext.FindOrCreate( TransportFeatureDriver.EnlistmentFact ) ) );
            builder.HostRoute( "Other", "Some.Command" );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    static async Task<PartyDescription> WaitForAsync( ILocalParty local, Func<PartyDescription, bool> condition )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( condition( local.Description ) ) return local.Description;
            await Task.Delay( 100 );
        }
        return local.Description;
    }

    [Test]
    public async Task the_routes_of_a_connected_remote_are_extended_and_withdrawn_when_it_disconnects_Async()
    {
        var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                             null,
                                                             [],
                                                             c => c["Local:PublicUrl"] = "https://admin.example.com",
                                                             [typeof( ApprovalPageFeatureDriver )] );
        var (sender, listener) = pair;
        try
        {
            (await sender.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
            string senderName = sender.ApplicationIdentityService.FullName;
            string listenerName = listener.ApplicationIdentityService.FullName;

            // The listener hosts both routes: the "Enlistment" one is derived from its approval page.
            var l = listener.ApplicationIdentityService.Description;
            l.Routes[TransportFeatureDriver.EnlistmentRouteName].ShouldBe( PartyRoute.Hosted( "https://admin.example.com/admin/app-identity/enlist", listenerName ) );
            l.Routes["Other"].ShouldBe( PartyRoute.Hosted( "Some.Command", listenerName ) );

            // The sender relays them: one hop more, the targets unchanged (it has no package for them).
            var s = await WaitForAsync( sender.ApplicationIdentityService, d => d.Routes.Count == 2 );
            s.Routes[TransportFeatureDriver.EnlistmentRouteName].ShouldBe( new PartyRoute( "https://admin.example.com/admin/app-identity/enlist", [senderName, listenerName] ) );
            s.Routes["Other"].ShouldBe( new PartyRoute( "Some.Command", [senderName, listenerName] ) );
        }
        finally
        {
            await listener.DisposeAsync();
        }
        // The listener is gone: its routes no more count.
        var after = await WaitForAsync( sender.ApplicationIdentityService, d => d.Routes.Count == 0 );
        after.Routes.ShouldBeEmpty( "A route counts only from a connected remote." );
        await sender.DisposeAsync();
    }

    [Test]
    public async Task without_public_URL_a_party_hosts_no_approval_page_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         null,
                                                                         [],
                                                                         null,
                                                                         [typeof( ApprovalPageFeatureDriver )] );
        var (sender, listener) = pair;
        (await sender.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
        var l = listener.ApplicationIdentityService.Description;
        l.Routes.ContainsKey( TransportFeatureDriver.EnlistmentRouteName ).ShouldBeFalse( "Never a URL that can't be reached." );
        l.Routes.ContainsKey( "Other" ).ShouldBeTrue();
    }

    [Test]
    public async Task a_configured_EnlistRemoteUrl_is_a_startup_error_Async()
    {
        await Should.ThrowAsync<Exception>( () => RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                                    null,
                                                                                    [],
                                                                                    c => c["Defaults:EnlistRemoteUrl"] = "https://enlist.example.com" ) );
    }
}
