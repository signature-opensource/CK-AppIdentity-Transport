using CK.Monitoring;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M8: the enlistment URL offered to a party the listener does not know (or doesn't trust).
/// <para>
/// The enlistment URL is the target of the "Enlistment" route of the local party concerned: the URL of an approval page
/// (a client application with the "Enlistment" fact), derived from the System, never configured.
/// </para>
/// <para>
/// Remote parties can be created dynamically, so an unknown party knocking in the hope of being accepted is the intended
/// onboarding flow, and answering it with "here is where you enlist" is the point. The disclosure half of M8 is therefore
/// by design. What is not by design: that reply is unsigned (the listener has no local keys to sign with when it doesn't
/// know the party at all), so the URL an operator is invited to act on arrives unauthenticated.
/// </para>
/// </summary>
[TestFixture]
public class EnlistUrlTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    /// <summary>
    /// Gives every local party an approval page: a client application "Admin" with the "Enlistment" fact. A local party
    /// hosts the "Enlistment" route when it also has a public URL.
    /// </summary>
    public sealed class ApprovalPageFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public ApprovalPageFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
        {
            builder.AddClientApplication( new ClientApplicationDescription( "Admin",
                                                                            "/admin",
                                                                            ClientApplicationDescription.FactContext.FindOrCreate( TransportFeatureDriver.EnlistmentFact ) ) );
        }

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<PartyDescriptionFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<PartyDescriptionFeatureDriver>() );
        services.AddSingleton<ApprovalPageFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<ApprovalPageFeatureDriver>() );
    }

    const string RootPage = "https://root.example.test/admin/app-identity/enlist";
    const string GhostPage = "https://ghost.example.test/admin/app-identity/enlist";

    /// <summary>
    /// A listener with an approval page, that hosts a tenant domain "Ghost" with its own approval page, and does not know
    /// anybody in it.
    /// </summary>
    Task<ApplicationIdentityService> CreateListenerAsync( string name, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Local:PublicUrl"] = "https://root.example.test";
            c["Parties:0:FullName"] = "Ghost/$Ghost";
            c["Parties:0:Local:PublicUrl"] = "https://ghost.example.test";
        }, ConfigureServices, token: token );

    /// <summary>A party in a domain that the listener has never heard of.</summary>
    Task<ApplicationIdentityService> CreateStrangerAsync( string domain, string name, string listenerName, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"{domain}/${name}";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:FullName"] = $"Test/${listenerName}";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, services => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );

    // The enlistment URL selects the pending approval of the party that receives it.
    static string ForParty( string page, ApplicationIdentityService party ) => $"{page}?party={Uri.EscapeDataString( party.FullName )}";

    static async Task<PeeringIssue?> WaitForIssueAsync( TransportManagerFeature f, int seconds, CancellationToken token )
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( DateTime.UtcNow < deadline )
        {
            var i = f.GetPeeringIssues().FirstOrDefault();
            if( i != null ) return i;
            await Task.Delay( 50, token );
        }
        return null;
    }

    [Test, CancelAfter( 90000 )]
    public async Task An_unknown_party_is_told_where_to_enlist_Async( CancellationToken token )
    {
        // The onboarding flow, end to end: a party nobody configured knocks, and must come away with
        // the enlistment URL of its domain surfaced as a peering issue an operator can act on.
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 2000 );
        await using var listener = await CreateListenerAsync( "M8Listen", token );
        await using var stranger = await CreateStrangerAsync( "Ghost", "M8Stranger", "M8Listen", token );

        var f = stranger.GetRequiredFeature<TransportManagerFeature>();
        var issue = await WaitForIssueAsync( f, 40, token );

        issue.ShouldNotBeNull( "The stranger must learn that it is unknown." );
        issue!.Kind.ShouldBe( PeeringIssueKind.RequiresRemoteCreation );
        issue.EnlistUrl.ShouldBe( ForParty( GhostPage, stranger ),
            "The caller claims the Ghost domain: the enlistment URL is the one of the approval page of the Ghost tenant domain." );

        logs.ExtractCurrentTexts().ShouldNotContain( t => t.Contains( "Protocol error" ),
            "An enlistment URL must not itself BE the protocol error: requiring an unsigned reply to carry a null URL " +
            "rejects exactly the reply that carries this one." );
    }

    [Test, CancelAfter( 90000 )]
    public async Task An_unknown_party_from_an_unknown_domain_gets_the_enlist_url_of_the_local_party_Async( CancellationToken token )
    {
        // No tenant domain of the caller's domain here: the root's approval page.
        await using var listener = await CreateListenerAsync( "M8RootListen", token );
        await using var stranger = await CreateStrangerAsync( "Elsewhere", "M8RootStranger", "M8RootListen", token );

        var issue = await WaitForIssueAsync( stranger.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull();
        issue!.Kind.ShouldBe( PeeringIssueKind.RequiresRemoteCreation );
        issue.EnlistUrl.ShouldBe( ForParty( RootPage, stranger ) );
    }

    [Test, CancelAfter( 90000 )]
    public async Task The_initiator_sends_its_enlist_url_to_the_listener_Async( CancellationToken token )
    {
        // Both parties know each other but trust nobody: both require an approval, and the initiator
        // sends its enlistment URL (its approval page) to the listener, that records it.
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M8BothListen";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = "$M8BothInit";
        }, services => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );
        await using var initiator = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M8BothInit";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Local:PublicUrl"] = "https://init.example.test";
            c["Parties:0:PartyName"] = "$M8BothListen";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureServices, token: token );

        var issue = await WaitForIssueAsync( listener.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull();
        issue!.Kind.ShouldBe( PeeringIssueKind.RequiresBothApproval );
        issue.EnlistUrl.ShouldBe( ForParty( "https://init.example.test/admin/app-identity/enlist", listener ),
                                  "The URL selects the pending approval of the party that receives it." );
    }

    [Test, CancelAfter( 90000 )]
    public async Task The_enlist_url_of_an_unknown_party_is_marked_unauthenticated_Async( CancellationToken token )
    {
        // The security half of M8, and the reason the URL must not be auto-followed. The reply that
        // carries it is unsigned — the listener has no local keys to sign with precisely because it
        // does not know us — so the URL is a claim by whoever answered the connection.
        await using var listener = await CreateListenerAsync( "M8AuthListen", token );
        await using var stranger = await CreateStrangerAsync( "Ghost", "M8AuthStranger", "M8AuthListen", token );

        var issue = await WaitForIssueAsync( stranger.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull();
        issue!.EnlistUrl.ShouldBe( ForParty( GhostPage, stranger ) );
        issue.IsEnlistUrlAuthenticated.ShouldBeFalse(
            "Nothing authenticated this URL. An on-path attacker, or anyone who wins the race to the " +
            "port, substitutes their own and the operator enlists with them. Following it is a trust " +
            "decision and must be surfaced as one." );
    }

    [Test, CancelAfter( 90000 )]
    public async Task The_listener_records_the_stranger_without_an_enlist_url_Async( CancellationToken token )
    {
        // PeeringIssue.EnlistUrl always means "where to go so that the OTHER side accepts us". The
        // listener sends its own URL, it does not record it: the URL it would record is the one the
        // remote replies with, and that reply is only requested for the approval issues.
        await using var listener = await CreateListenerAsync( "M8SelfListen", token );
        await using var stranger = await CreateStrangerAsync( "Ghost", "M8SelfStranger", "M8SelfListen", token );

        var issue = await WaitForIssueAsync( listener.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull( "The listener records the stranger as an unknown incoming." );
        issue!.Kind.ShouldBe( PeeringIssueKind.IncomingUnknown );
        issue.EnlistUrl.ShouldBeNull(
            "The listener sent its URL to the stranger; it has no URL of the stranger's to record." );
    }

    [Test, CancelAfter( 90000 )]
    public async Task A_configured_EnlistRemoteUrl_fails_the_setup_Async( CancellationToken token )
    {
        // The enlistment URL is derived from the System: the former configuration is an error, not silently ignored.
        await Should.ThrowAsync<Exception>( () => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$M8Configured";
            c["Defaults:EnlistRemoteUrl"] = "https://enlist.example.test/join";
        }, ConfigureServices, token: token ) );
    }
}
