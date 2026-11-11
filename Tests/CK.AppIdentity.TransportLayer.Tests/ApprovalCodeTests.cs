using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
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
/// The approval code (a short authentication string): both parties compute it from their names, their keys and a
/// nonce of each side (committed, answered, then revealed by the connection attempts), and an operator approves a
/// remote with the code read on the remote itself.
/// </summary>
[TestFixture]
public class ApprovalCodeTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    async Task<(ApplicationIdentityService Listener, ApplicationIdentityService Initiator)> CreatePairAsync( string name, CancellationToken token )
    {
        // The pins are kept in the shared test store: a previous run must not have approved them already.
        PeerStore.ClearRemoteTrust( $"Test/${name}Listen" );
        PeerStore.ClearRemoteTrust( $"Test/${name}Init" );
        var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}Listen";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = $"${name}Init";
        }, ConfigureFastClock, token: token );
        var initiator = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}Init";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = $"${name}Listen";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
        }, ConfigureFastClock, token: token );
        return (listener, initiator);
    }

    static async Task<T?> WaitForAsync<T>( Func<T?> get, int seconds, CancellationToken token ) where T : class
    {
        var deadline = DateTime.UtcNow.AddSeconds( seconds );
        while( DateTime.UtcNow < deadline )
        {
            var v = get();
            if( v != null ) return v;
            await Task.Delay( 50, token );
        }
        return null;
    }

    static PeeringIssue? Issue( ApplicationIdentityService s ) => s.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault();

    static string? Code( ApplicationIdentityService s ) => Issue( s )?.ApprovalCode;

    [Test, CancelAfter( 120000 )]
    public async Task both_parties_show_the_same_code_and_each_one_approves_the_other_with_it_Async( CancellationToken token )
    {
        var (listener, initiator) = await CreatePairAsync( "SasBoth", token );
        await using var l = listener;
        await using var i = initiator;

        var listenerCode = await WaitForAsync( () => Code( listener ), 40, token );
        var initiatorCode = await WaitForAsync( () => Code( initiator ), 40, token );
        listenerCode.ShouldNotBeNull( "The listener computes the code once the initiator revealed its nonce." );
        initiatorCode.ShouldNotBeNull( "The initiator computes the code once the listener answered its nonce." );
        listenerCode.ShouldBe( initiatorCode, "Both sides compute the same code." );
        listenerCode.ShouldMatch( @"^\d{4}-\d{4}$" );
        Issue( listener )!.Kind.ShouldBe( PeeringIssueKind.RequiresBothApproval );
        Issue( initiator )!.Kind.ShouldBe( PeeringIssueKind.RequiresBothApproval );

        // Each operator enters the code read on the other party (here, the same code).
        Issue( listener )!.TryApprove( TestHelper.Monitor, initiatorCode.Replace( "-", " " ) ).ShouldBeTrue( "The separators are ignored." );
        Issue( initiator )!.TryApprove( TestHelper.Monitor, listenerCode ).ShouldBeTrue();

        var connected = await WaitForAsync( () => initiator.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected
                                                    ? "Connected"
                                                    : null,
                                            40,
                                            token );
        connected.ShouldNotBeNull( "Both keys are pinned: the parties connect." );
    }

    [Test, CancelAfter( 120000 )]
    public async Task the_code_is_stable_across_the_attempts_and_a_wrong_code_is_refused_Async( CancellationToken token )
    {
        var (listener, initiator) = await CreatePairAsync( "SasStable", token );
        await using var l = listener;
        await using var i = initiator;

        var code = await WaitForAsync( () => Code( initiator ), 40, token );
        code.ShouldNotBeNull();
        // The initiator may know the code before the listener has created its issue (a loaded machine): wait for it.
        var first = await WaitForAsync( () => Issue( listener ), 40, token );
        first.ShouldNotBeNull();
        var updated = first.LastUpdated;
        // A few more attempts (the initiator retries every 5 seconds).
        (await WaitForAsync( () => Issue( listener )!.LastUpdated > updated ? "next" : null, 40, token )).ShouldNotBeNull();
        (await WaitForAsync( () => Code( listener ), 40, token )).ShouldBe( code, "The nonces are kept across the attempts: the code doesn't change." );
        Code( initiator ).ShouldBe( code );

        var issue = Issue( listener )!;
        var wrong = code == "1234-5678" ? "8765-4321" : "1234-5678";
        issue.TryApprove( TestHelper.Monitor, wrong ).ShouldBeFalse( "A wrong code is refused." );
        issue.TryApprove( TestHelper.Monitor, "123" ).ShouldBeFalse( "8 digits are expected." );
        issue.TryApprove( TestHelper.Monitor, "1234x5678" ).ShouldBeFalse( "Only spaces and dashes separate the digits." );
        listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedIdentity.ShouldBeNull( "Nothing has been approved." );
    }
}
