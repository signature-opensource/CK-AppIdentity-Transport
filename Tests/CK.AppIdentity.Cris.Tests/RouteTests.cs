using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Text.Json;
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
                                                                            ClientApplicationFacts.Create( (TransportFeatureDriver.EnlistmentFact, "app-identity/enlist") ) ) );
            builder.HostRoute( "Other", "Some.Command" );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    /// <summary>
    /// Hosts the "MailSender" route (without target: the host is what is reached).
    /// </summary>
    public sealed class MailHostFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public MailHostFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder ) => builder.HostRoute( "MailSender" );

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
            l.Routes[TransportFeatureDriver.EnlistmentRouteName].ShouldHaveSingleItem().ShouldBe( PartyRoute.Hosted( "https://admin.example.com/admin/app-identity/enlist", listenerName ) );
            l.Routes["Other"].ShouldHaveSingleItem().ShouldBe( PartyRoute.Hosted( "Some.Command", listenerName ) );

            // The sender relays them: one hop more, the targets unchanged (it has no package for them).
            var s = await WaitForAsync( sender.ApplicationIdentityService, d => d.Routes.Count == 2 );
            s.Routes[TransportFeatureDriver.EnlistmentRouteName].ShouldHaveSingleItem().ShouldBe( new PartyRoute( "https://admin.example.com/admin/app-identity/enlist", [senderName, listenerName] ) );
            s.Routes["Other"].ShouldHaveSingleItem().ShouldBe( new PartyRoute( "Some.Command", [senderName, listenerName] ) );
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

    /// <summary>
    /// The pending approvals travel the "Enlistment" route toward the approval page: A hosts the page, B is connected to A
    /// and holds a pending approval of an unknown key of D.
    /// </summary>
    [Test]
    public async Task a_pending_approval_is_collected_along_the_Enlistment_route_up_to_its_host_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         c => c["Local:PublicUrl"] = "https://admin.example.com",
                                                                         [typeof( ApprovalPageFeatureDriver )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$D";
                                                                             c["Parties:1:AutoTrustKey"] = "Never";
                                                                         } );
        var (a, b) = pair;
        (await a.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        var route = TransportFeatureDriver.EnlistmentRouteName;
        (await WaitForAsync( b.ApplicationIdentityService, d => d.Routes.ContainsKey( route ) )).Routes[route].ShouldHaveSingleItem().Host.ShouldBe( aName );

        // D trusts B on first contact, B doesn't trust D: B must approve D's key (RequiresLocalApproval). D hosts a route.
        await using var d = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$D",
                                                                  RunningApplication.WithHeartBeat(),
                                                                  [typeof( MailHostFeatureDriver )] );
        string dName = d.ApplicationIdentityService.FullName;

        var atHost = await WaitForAsync( a.ApplicationIdentityService, x => x.Collected.ContainsKey( route ) );
        var item = atHost.Collected[route].ShouldHaveSingleItem();
        item.Path.ShouldBe( [bName, aName], "The holder first, then each hop up to the host." );
        item.Holder.ShouldBe( bName );
        b.ApplicationIdentityService.Description.Collected[route].ShouldHaveSingleItem().ShouldBe( CollectedItem.Own( item.Value, bName ) );

        var issue = b.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().Single( i => i.FullName == dName );
        using( var json = JsonDocument.Parse( item.Value ) )
        {
            var v = json.RootElement;
            v.GetProperty( "Party" ).GetString().ShouldBe( dName );
            v.GetProperty( "Fingerprint" ).GetString().ShouldBe( issue.RemoteKeyFingerprintForApproval );
            v.GetProperty( "Kind" ).GetString().ShouldBe( "Local" );
            v.GetProperty( "Since" ).GetDateTime().ShouldBe( issue.ApprovalPendingSince!.Value );
            v.EnumerateObject().Select( p => p.Name ).ShouldBe( ["Party", "Fingerprint", "Kind", "Since", "Routes"], "Never the approval code." );
        }
        // The routes D states that it hosts travel with its pending approval: the operator can authorize them with it.
        issue.RemoteHostedRoutes.ShouldBe( ["MailSender"] );
        TransportFeatureDriver.TryReadPendingApprovalValue( item.Value, out var pending ).ShouldBeTrue();
        pending.HostedRoutes.ShouldBe( ["MailSender"] );

        // Approved: D connects, the issue is resolved and the item disappears from the holder and from the host.
        issue.AcceptRemoteIdentity( TestHelper.Monitor ).ShouldBeTrue();
        (await WaitForAsync( a.ApplicationIdentityService, x => x.Collected.Count == 0 )).Collected.ShouldBeEmpty();
        b.ApplicationIdentityService.Description.Collected.ShouldBeEmpty();
    }
}
