using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The two negotiation budgets are separate numbers because they answer separate questions.
/// <para>
/// A listener's budget bounds how long a stranger who has authenticated nothing holds one of the
/// slots <see cref="TransportManagerFeature.MaxConcurrentNegotiation"/> counts: short, fixed, a
/// denial-of-service control. An initiator's budget is a reachability allowance for a party the
/// operator configured, where there is no such exposure — and it covers more, since its window opens
/// before the TCP connect and so contains the connect, about two and a half round trips, and any
/// retransmission.
/// </para>
/// <para>
/// Serving both from one constant forces a choice between refusing a satellite link and handing an
/// unauthenticated peer five times the hold, which is why the value is per remote.
/// </para>
/// <para>
/// Only the initiator side is configurable. The listener side is a constant on the internal
/// TransportManager, unreachable from configuration and from here — deliberately, since it is the
/// one an attacker would want raised.
/// </para>
/// </summary>
[TestFixture]
public class NegotiationTimeoutTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateAsync( string name, Action<MutableConfigurationSection> remote, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = $"${name}Peer";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37199";
            remote( c );
        }, ConfigureFastClock, token: token );

    [Test, CancelAfter( 30000 )]
    public async Task A_remote_without_configuration_follows_the_manager_default_Async( CancellationToken token )
    {
        await using var s = await CreateAsync( "NTDefault", _ => { }, token );
        var f = s.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var settings = s.GetRequiredFeature<TransportManagerFeature>();

        settings.DefaultOutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 15 ) );
        f.OutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 15 ) );

        // Read through rather than captured: raising the default must still reach every remote that
        // did not ask for something specific, without restarting anything.
        settings.DefaultOutgoingNegotiationTimeout = TimeSpan.FromSeconds( 45 );
        f.OutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 45 ) );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_remote_can_set_its_own_budget_Async( CancellationToken token )
    {
        // The reason this is per remote: one fleet on a LAN and another behind a satellite hop cannot
        // share a number, and neither is wrong.
        await using var s = await CreateAsync( "NTOwn", c => c["Parties:0:NegotiationTimeout"] = "90", token );
        var f = s.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var settings = s.GetRequiredFeature<TransportManagerFeature>();

        f.OutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 90 ) );

        settings.DefaultOutgoingNegotiationTimeout = TimeSpan.FromSeconds( 5 );
        f.OutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 90 ),
            "A remote that stated its own value keeps it: the default is a fallback, not a cap." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_unusable_configured_value_falls_back_rather_than_failing_the_start_Async( CancellationToken token )
    {
        // A typo in this entry must not stop the service: it is a tuning knob, not a security switch,
        // and the failure mode of refusing to start is worse than the failure mode of using 15 seconds.
        await using var s = await CreateAsync( "NTBad", c => c["Parties:0:NegotiationTimeout"] = "soon", token );
        var f = s.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        f.OutgoingNegotiationTimeout.ShouldBe( TimeSpan.FromSeconds( 15 ) );
    }

}
