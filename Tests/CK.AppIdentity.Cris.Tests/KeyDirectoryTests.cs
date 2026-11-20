using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Monitoring;
using CK.Testing.Engine.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The <see cref="AnchoredKeyDirectory"/>: three parties in a star, "Test/$Sender" &gt; "Test/$Listener" &lt; "Test/$C".
/// The sender anchors C and has no channel to it: it gets the keys of C through its hub, the listener (see
/// <see cref="TenantCommandTests.SingleRemoteHub"/>).
/// </summary>
[TestFixture]
public class KeyDirectoryTests
{
    static readonly Type[] _common = [typeof( IPartyRoutedCommand ),
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CK.Cris.CrisBackgroundExecutorService ),
                                      typeof( CK.Cris.RawCrisReceiver ),
                                      typeof( IPartySealedResult ),
                                      typeof( IGetKeyEventsQCommand ),
                                      typeof( IPartyKeyEvents ),
                                      typeof( KeyEventsHandler ),
                                      typeof( AnchoredKeyDirectory )];

    const string Purpose = "Test.KeyDirectory";

    static readonly byte[] _data = [1, 2, 3];

    static ApplicationSignature Sign( RunningApplication app )
        => app.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Sign( Purpose, _data, DateTime.UtcNow.AddMinutes( 5 ) );

    static async Task<SignatureVerdict> CheckAsync( RunningApplication app, string fullName, ApplicationSignature signature )
    {
        using var scope = app.CreateScopeServices();
        return await app.Services.GetRequiredService<AnchoredKeyDirectory>()
                                 .CheckAsync( TestHelper.Monitor, scope.ServiceProvider, app.ApplicationIdentityService, fullName, Purpose, _data, signature );
    }

    // Starts C first (it connects to the listener once it is up), then the pair: the sender anchors C with the
    // checkpoint given (C's own checkpoint when null).
    static async Task<(RunningApplication A, RunningApplication B, RunningApplication C, RunningApplicationPair Pair)> StartAsync( Func<KeyCheckpoint, string>? anchor = null,
                                                                                                                                       int rotations = 0,
                                                                                                                                       bool withHub = true )
    {
        var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                      isSender: true,
                                                      c => c["FullName"] = "Test/$C",
                                                      RunningApplication.WithHeartBeat(),
                                                      _common );
        var cKeys = c.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        var checkpoint = cKeys.Checkpoint;
        // C rotates after the checkpoint is taken: more than a usual tail of events.
        for( int i = 0; i < rotations; ++i ) cKeys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        string cName = c.ApplicationIdentityService.FullName.Path;
        var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                             senderConfiguration: s => s[$"Local:KeyManagement:TrustAnchors:{cName}"] = anchor?.Invoke( checkpoint ) ?? checkpoint.ToString(),
                                                             senderTypes: withHub ? [.. _common, typeof( TenantCommandTests.SingleRemoteHub )] : _common,
                                                             listenerConfiguration: l =>
                                                             {
                                                                 l["Parties:1:PartyName"] = "$C";
                                                                 l["Parties:1:KeyManagement:AutoTrustKey"] = "Once";
                                                             },
                                                             listenerTypes: _common );
        // The star: the sender and C are connected to the listener.
        (await pair.Sender.CrisChannel.WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 30 ) )).ShouldBeTrue();
        var b = pair.Listener.ApplicationIdentityService;
        for( int i = 0; i < 100 && !b.Remotes.Any( r => r.FullName.Path == cName ); ++i ) await Task.Delay( 100 );
        (await b.Remotes.Single( r => r.FullName.Path == cName ).GetRequiredFeature<CrisChannelFeature>().WaitForAcceptedCommandsAsync( TimeSpan.FromSeconds( 30 ) )).ShouldBeTrue();
        return (pair.Sender, pair.Listener, c, pair);
    }

    [Test]
    public async Task the_keys_of_an_anchored_party_are_fetched_through_the_hub_and_verified_from_its_anchor_Async()
    {
        var (a, b, c, pair) = await StartAsync( rotations: 10 );
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        a.ApplicationIdentityService.Remotes.ShouldNotContain( r => r.FullName.Path == cName, "No channel from the sender to C." );

        // C rotated 10 times since its anchor: its events from the anchor come in one fetch (the window).
        (await CheckAsync( a, cName, Sign( c ) )).ShouldBe( SignatureVerdict.Valid );
        var keys = a.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( cName ).ShouldNotBeNull();
        keys.Head.ShouldNotBeNull().Seq.ShouldBe( 10 );

        // C rotates again: the next fetch is too early (at most one every 5 seconds per party), then it catches up from
        // the head held.
        c.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue();
        var signature = Sign( c );
        (await CheckAsync( a, cName, signature )).ShouldBe( SignatureVerdict.UnknownIssuer );
        await Task.Delay( AnchoredKeyDirectory.MinFetchInterval );
        (await CheckAsync( a, cName, signature )).ShouldBe( SignatureVerdict.Valid );
        keys.Head!.Seq.ShouldBe( 11 );
    }

    [Test]
    public async Task events_that_dont_match_the_anchor_are_refused_Async()
    {
        // The digest of the anchor is not the one of C: whatever comes back through the hub, it is checked, never believed.
        var (a, b, c, pair) = await StartAsync( anchor: cp => $"{cp.Seq}:{new string( '0', 64 )}" );
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await CheckAsync( a, cName, Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( l => l.StartsWith( $"The key events received for '{cName}' don't match its trust anchor" ) );
        }
        a.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( cName ).ShouldNotBeNull().Head.ShouldBeNull();
    }

    [Test]
    public async Task without_a_hub_the_signature_of_a_party_that_is_not_a_remote_is_refused_Async()
    {
        var (a, b, c, pair) = await StartAsync( withHub: false );
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await CheckAsync( a, cName, Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( l => l.Contains( "neither a remote nor reachable through a hub" ) );
        }
        // A party that is not anchored is never looked up.
        (await CheckAsync( a, b.ApplicationIdentityService.FullName.Path, Sign( b ) )).ShouldBe( SignatureVerdict.Refused );
    }

    [Test]
    public async Task a_revoked_name_is_refused_in_the_routed_commands_Async()
    {
        var (a, b, c, pair) = await StartAsync();
        await using var _ = c;
        await using var __ = pair;
        string aName = a.ApplicationIdentityService.FullName.Path;
        string cName = c.ApplicationIdentityService.FullName.Path;
        // Another identity than the actual ones: only the names are banned, nobody is cut.
        var other = new byte[KeyEvent.HashSize];
        other[0] = 7;
        var bKeys = b.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();

        // The listener (a hop) refuses a routed command that comes from a banned name.
        await bKeys.SetRevocationsAsync( TestHelper.Monitor, [new RevocationEntry( aName, other, DateTime.UtcNow, nameBanned: true )] );
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await CheckAsync( a, cName, Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( l => l.Contains( $"its Via contains '{aName}', a revoked party." ) );
        }
        // Readmitted: the name is accepted again.
        await bKeys.SetRevocationsAsync( TestHelper.Monitor, [new RevocationEntry( aName, other, DateTime.UtcNow, nameBanned: false )] );
        await Task.Delay( AnchoredKeyDirectory.MinFetchInterval );
        (await CheckAsync( a, cName, Sign( c ) )).ShouldBe( SignatureVerdict.Valid );
    }
}
