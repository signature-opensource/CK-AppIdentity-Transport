using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M7: the cap on peering issues for truly unknown remotes.
/// <para>
/// Anyone who can reach the port can make the listener record an issue under any full name they
/// like — no trust decision has been taken at that point. <see cref="TransportManagerFeature.MaxUnknownRemoteCount"/>
/// is what stops that from growing without bound, and what stops it from washing away the
/// operator's real diagnostics.
/// </para>
/// <para>
/// A count tracked by hand does neither, and fails silently. Incremented once per new unknown
/// remote but not decremented for the entries the very same call trims, it drifts above reality;
/// each trim then computes a larger excess than it should, and from the ninth unknown remote on,
/// every new one flushes every other — a cap of 5 behaving as a cap of 1. Trimming by descending
/// LastUpdated is the matching mistake: it keeps the stalest entries and discards the freshest.
/// </para>
/// </summary>
[TestFixture]
public class UnknownRemoteIssueTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateListenerAsync( string localName, string knownRemote, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = knownRemote;
        }, ConfigureFastClock, token: token );

    /// <summary>
    /// One connection from a party the listener has never heard of: a well-formed, correctly
    /// self-signed InitialMessage under <paramref name="ghostName"/>. Returns once the listener has
    /// recorded the issue, so that the caller controls the order of LastUpdated.
    /// </summary>
    async Task KnockAsUnknownAsync( TransportManagerFeature feature, string ghostName, CancellationToken token )
    {
        using var key = PeerIdentity.Create( ghostName );
        using var ephemeral = new PeerEphemeral();
        var initial = PeerMessages.InitialMessage( ghostName,
                                                   instanceId: "M7Instance",
                                                   availableProtocols: Array.Empty<string>(),
                                                   expectedCommonProtocolCount: 0,
                                                   nonceCreationTime: _systemClock.UtcNow,
                                                   nonce: BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) ),
                                                   ephemeralPublicKey: ephemeral.PublicKey,
                                                   macCapabilities: RunPhaseProtection.LocalCapabilities,
                                                   signWith: key );
        await using( var c = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c.SendZeroFrameAsync( initial, token );
            // Whatever the listener answers (it declines to sign a reply to a party it does not
            // know) it has taken its decision by the time it writes or closes.
            try { await c.ReadFrameAsync( token ); }
            catch( System.IO.EndOfStreamException ) { }
            catch( System.IO.IOException ) { }
            catch( System.Net.Sockets.SocketException ) { }
        }
        var deadline = DateTime.UtcNow.AddSeconds( 20 );
        while( feature.Find( ghostName ) == null )
        {
            if( DateTime.UtcNow > deadline ) Throw.CKException( $"Timeout: no peering issue recorded for '{ghostName}'." );
            await Task.Delay( 20, token );
        }
    }

    static string[] UnknownNames( TransportManagerFeature feature )
        => feature.GetPeeringIssues().Where( i => i.Remote == null ).Select( i => i.FullName ).ToArray();

    /// <summary>
    /// Knocks <paramref name="count"/> times under distinct never-seen names, oldest first.
    /// The clock is stepped between knocks so LastUpdated is strictly increasing: DateTime.UtcNow
    /// has a ~15 ms resolution on Windows and several knocks would otherwise share a timestamp,
    /// which would make any assertion about *which* entries survive meaningless.
    /// </summary>
    async Task<string[]> FloodAsync( TransportManagerFeature feature, string prefix, int count, CancellationToken token )
    {
        var names = new List<string>();
        for( int i = 0; i < count; ++i )
        {
            var ghost = $"Test/${prefix}Ghost{i}/#Dev";
            names.Add( ghost );
            await KnockAsUnknownAsync( feature, ghost, token );
            _systemClock.Offset += TimeSpan.FromSeconds( 1 );
        }
        return names.ToArray();
    }

    [Test, CancelAfter( 120000 )]
    public async Task The_unknown_remote_cap_holds_under_a_flood_Async( CancellationToken token )
    {
        // The counter drift, directly. 12 unknown remotes against a cap of 5: the surviving count
        // must be 5. A drifting counter collapses it to 1 from the ninth knock on, at which point a
        // peer sending random full names erases every other diagnostic at will.
        const string known = "$M7CapKnown";
        PeerStore.ClearRemoteTrust( $"Test/{known}" );
        await using var listener = await CreateListenerAsync( "$M7CapListen", known, token );
        var feature = listener.GetRequiredFeature<TransportManagerFeature>();
        feature.MaxUnknownRemoteCount.ShouldBe( 5, "The default cap this test is written against." );

        await FloodAsync( feature, "M7Cap", 12, token );

        feature.UnknownRemoteCount.ShouldBe( 5,
            "The cap is the cap. A drifting counter makes every new unknown remote trim more than it " +
            "should, until only one survives." );
        UnknownNames( feature ).Length.ShouldBe( 5, "And the dictionary agrees with the count." );
    }

    [Test, CancelAfter( 120000 )]
    public async Task The_cap_keeps_the_most_recent_unknown_remotes_Async( CancellationToken token )
    {
        // The trim ordering. What an operator wants to see is what just happened, so the entries
        // that go are the stalest ones. OrderByDescending( LastUpdated ) discards exactly the
        // entries worth keeping.
        const string known = "$M7OrdKnown";
        PeerStore.ClearRemoteTrust( $"Test/{known}" );
        await using var listener = await CreateListenerAsync( "$M7OrdListen", known, token );
        var feature = listener.GetRequiredFeature<TransportManagerFeature>();

        var names = await FloodAsync( feature, "M7Ord", 8, token );

        var survivors = UnknownNames( feature );
        survivors.Length.ShouldBe( 5 );
        survivors.Order().ShouldBe( names[^5..].Order(),
            "The five most recent knocks survive and the three oldest are trimmed." );
    }

    [Test, CancelAfter( 120000 )]
    public async Task A_known_remote_issue_is_not_trimmed_by_unknown_remotes_Async( CancellationToken token )
    {
        // The cap exists to bound what an anonymous peer can create. It must not reach the issues
        // that belong to a configured party: those are the diagnostics the operator actually
        // configured the party to get.
        const string known = "$M7KeepKnown";
        PeerStore.ClearRemoteTrust( $"Test/{known}" );
        await using var listener = await CreateListenerAsync( "$M7KeepListen", known, token );
        var feature = listener.GetRequiredFeature<TransportManagerFeature>();

        await FloodAsync( feature, "M7Keep", 12, token );

        feature.UnknownRemoteCount.ShouldBe( 5 );
        feature.GetPeeringIssues().Count( i => i.Remote != null )
               .ShouldBe( feature.IssueCount - 5,
                          "Only the unknown-remote issues are subject to the cap." );
    }
}
