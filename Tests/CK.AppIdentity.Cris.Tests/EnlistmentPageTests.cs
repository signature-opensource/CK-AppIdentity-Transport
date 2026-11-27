using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing.Engine.AppIdentity.Cris;
using NUnit.Framework;
using Shouldly;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The approval page of the System is a fact of a client application (<see cref="TransportFeatureDriver.EnlistmentFact"/>):
/// its party has it, a direct remote reads it from its description (nothing is announced beyond one hop).
/// </summary>
[TestFixture]
public class EnlistmentPageTests
{
    /// <summary>
    /// A client application that is an approval page.
    /// </summary>
    [PartyFeature( "ApprovalPage", TypeActivation.ByDefault )]
    public sealed class ApprovalPageFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public ApprovalPageFeatureDriver( ApplicationIdentityService s ) : base( s ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
        {
            builder.AddClientApplication( new ClientApplicationDescription( "Admin",
                                                                            "/admin",
                                                                            ClientApplicationFacts.Create( (TransportFeatureDriver.EnlistmentFact, "app-identity/enlist") ) ) );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    static async Task<string?> WaitForPageAsync( ILocalParty local )
    {
        for( int i = 0; i < 100; ++i )
        {
            var u = TransportFeatureDriver.FindEnlistmentPageUrl( local );
            if( u != null ) return u;
            await Task.Delay( 100 );
        }
        return null;
    }

    [Test]
    public async Task the_approval_page_is_a_fact_read_by_a_direct_remote_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         null,
                                                                         [],
                                                                         c => c["Local:PublicUrl"] = "https://admin.example.com",
                                                                         [typeof( ApprovalPageFeatureDriver )] );
        var (sender, listener) = pair;
        (await sender.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 10 ) )).ShouldBeTrue();
        const string page = "https://admin.example.com/admin/app-identity/enlist";
        TransportFeatureDriver.GetEnlistmentPageUrl( listener.ApplicationIdentityService.Description, "listener" ).ShouldBe( page );
        TransportFeatureDriver.FindEnlistmentPageUrl( listener.ApplicationIdentityService ).ShouldBe( page, "Its own page." );
        (await WaitForPageAsync( sender.ApplicationIdentityService )).ShouldBe( page, "The page of its direct remote." );
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
        TransportFeatureDriver.FindEnlistmentPageUrl( listener.ApplicationIdentityService ).ShouldBeNull( "Never a URL that can't be reached." );
        TransportFeatureDriver.FindEnlistmentPageUrl( sender.ApplicationIdentityService ).ShouldBeNull();
    }

    [Test]
    public async Task in_Dev_an_unknown_key_of_the_Transport_feature_is_ignored_Async()
    {
        // The "Transport" section is read through its model: "RouteHosts" is not one of its keys. The "#Dev" environment
        // is not strict: a warning (it fails the start in strict mode).
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         null,
                                                                         [],
                                                                         c => c["Local:Transport:RouteHosts:Enlistment:0"] = "Test/$Admin" );
    }
}
