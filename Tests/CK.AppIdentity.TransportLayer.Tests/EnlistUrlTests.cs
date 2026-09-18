using CK.Core;
using CK.Monitoring;
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
/// Finding M8: the enlistment URL offered to a party the listener does not know.
/// <para>
/// Remote parties can be created dynamically, so an unknown party knocking in the hope of being
/// accepted is the intended onboarding flow, and answering it with "here is where you enlist" is the
/// point. The disclosure half of M8 is therefore by design.
/// </para>
/// <para>
/// What is not by design: that reply is unsigned (<c>ZeroProtocol.Negotiation.cs:371</c> writes false
/// for the signature when the listener has no local keys to sign with, which is exactly the unknown
/// case), so the URL an operator is invited to act on arrives unauthenticated.
/// </para>
/// </summary>
[TestFixture]
public class EnlistUrlTests
{
    const string EnlistUrl = "https://enlist.example.test/{DomainName}/join";
    const string ExpectedUrl = "https://enlist.example.test/Ghost/join";

    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    /// <summary>
    /// A listener that hosts a tenant domain "Ghost" carrying an EnlistRemoteUrl, and does not know
    /// anybody in it. GetEnlistRemoteUrl resolves an unknown party's URL through
    /// TenantDomains.FirstOrDefault( d =&gt; d.DomainName == domainName ), so without this tenant the
    /// URL is null and nothing is offered at all.
    /// </summary>
    Task<ApplicationIdentityService> CreateListenerAsync( string name, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["AlwaysListening"] = "True";
            c["AutoTrustKey"] = "Never";
            c["Parties:0:FullName"] = "Ghost/$Ghost";
            c["Parties:0:EnlistRemoteUrl"] = EnlistUrl;
        }, ConfigureFastClock, token: token );

    /// <summary>A party in the "Ghost" domain that the listener has never heard of.</summary>
    Task<ApplicationIdentityService> CreateStrangerAsync( string name, string listenerName, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Ghost/${name}";
            c["AutoTrustKey"] = "Never";
            c["Parties:0:FullName"] = $"Test/${listenerName}";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureFastClock, token: token );

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
        // the enlistment URL surfaced as a peering issue an operator can act on.
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 2000 );
        await using var listener = await CreateListenerAsync( "M8Listen", token );
        await using var stranger = await CreateStrangerAsync( "M8Stranger", "M8Listen", token );

        var f = stranger.GetRequiredFeature<TransportManagerFeature>();
        var issue = await WaitForIssueAsync( f, 40, token );

        issue.ShouldNotBeNull( "The stranger must learn that it is unknown." );
        issue!.Kind.ShouldBe( PeeringIssueKind.RequiresRemoteCreation );
        issue.EnlistUrl.ShouldBe( ExpectedUrl,
            "The listener resolved an enlistment URL for the Ghost tenant domain and sent it: the " +
            "whole point of answering an unknown party is to tell it where to enlist." );

        logs.ExtractCurrentTexts().ShouldNotContain( t => t.Contains( "Protocol error" ),
            "Configuring an EnlistRemoteUrl used to BE the protocol error: the initiator required an " +
            "unsigned reply to carry a null URL, which is exactly the reply that carries this one." );
    }

    [Test, CancelAfter( 90000 )]
    public async Task The_enlist_url_of_an_unknown_party_is_marked_unauthenticated_Async( CancellationToken token )
    {
        // The security half of M8, and the reason the URL must not be auto-followed. The reply that
        // carries it is unsigned — the listener has no local keys to sign with precisely because it
        // does not know us — so the URL is a claim by whoever answered the connection.
        await using var listener = await CreateListenerAsync( "M8AuthListen", token );
        await using var stranger = await CreateStrangerAsync( "M8AuthStranger", "M8AuthListen", token );

        var issue = await WaitForIssueAsync( stranger.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull();
        issue!.EnlistUrl.ShouldBe( ExpectedUrl );
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
        // remote replies with, and that reply is only requested for RequiresLocal/BothApproval.
        // Pinning this because it is the natural thing to get wrong when reading the finding.
        await using var listener = await CreateListenerAsync( "M8SelfListen", token );
        await using var stranger = await CreateStrangerAsync( "M8SelfStranger", "M8SelfListen", token );

        var issue = await WaitForIssueAsync( listener.GetRequiredFeature<TransportManagerFeature>(), 40, token );
        issue.ShouldNotBeNull( "The listener records the stranger as an unknown incoming." );
        issue!.Kind.ShouldBe( PeeringIssueKind.IncomingUnknwon );
        issue.EnlistUrl.ShouldBeNull(
            "The listener sent its URL to the stranger; it has no URL of the stranger's to record." );
    }
}
