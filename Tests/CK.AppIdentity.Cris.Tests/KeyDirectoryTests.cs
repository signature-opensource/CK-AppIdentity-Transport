using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The <see cref="AnchoredKeyDirectory"/>: three parties in a chain, "Test/$Sender" &gt; "Test/$Listener" &lt; "Test/$C".
/// C hosts the route "Keys", the sender anchors C and has no channel to it: it gets the keys of C along the route.
/// </summary>
[TestFixture]
public class KeyDirectoryTests
{
    public sealed class KeysRouteHostFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public KeysRouteHostFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder ) => builder.HostRoute( "Keys", party.FullName.Path );

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

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

    static async Task<SignatureVerdict> CheckAsync( RunningApplication app, string fullName, string routeName, ApplicationSignature signature )
    {
        using var scope = app.CreateScopeServices();
        return await app.Services.GetRequiredService<AnchoredKeyDirectory>()
                                 .CheckAsync( TestHelper.Monitor, scope.ServiceProvider, app.ApplicationIdentityService, fullName, routeName, Purpose, _data, signature );
    }

    static async Task<bool> WaitForRouteAsync( ILocalParty local, string name )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( local.Description.Routes.ContainsKey( name ) ) return true;
            await Task.Delay( 100 );
        }
        return false;
    }

    // Starts C first (it connects to the listener once it is up), then the pair: the sender anchors C with the
    // checkpoint given (C's own checkpoint when null).
    static async Task<(RunningApplication A, RunningApplication B, RunningApplication C, RunningApplicationPair Pair)> StartAsync( Func<KeyCheckpoint, string>? anchor = null,
                                                                                                                                       int rotations = 0 )
    {
        var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                      isSender: true,
                                                      c => c["FullName"] = "Test/$C",
                                                      RunningApplication.WithHeartBeat(),
                                                      [.. _common, typeof( KeysRouteHostFeatureDriver )] );
        var cKeys = c.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>();
        var checkpoint = cKeys.Checkpoint;
        // C rotates after the checkpoint is taken: more than a usual tail of events.
        for( int i = 0; i < rotations; ++i ) cKeys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        string cName = c.ApplicationIdentityService.FullName.Path;
        var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                             senderConfiguration: s => s[$"Local:TrustAnchors:{cName}"] = anchor?.Invoke( checkpoint ) ?? checkpoint.ToString(),
                                                             senderTypes: _common,
                                                             listenerConfiguration: l =>
                                                             {
                                                                 l["Parties:1:PartyName"] = "$C";
                                                                 l["Parties:1:AutoTrustKey"] = "Once";
                                                             },
                                                             listenerTypes: [.. _common, typeof( RoutedCommandTests.RouteHostFeatureDriver )] );
        (await WaitForRouteAsync( pair.Sender.ApplicationIdentityService, "Keys" )).ShouldBeTrue( "The route of C reaches the sender through the listener." );
        return (pair.Sender, pair.Listener, c, pair);
    }

    [Test]
    public async Task the_keys_of_an_anchored_party_are_fetched_along_its_route_and_verified_from_its_anchor_Async()
    {
        var (a, b, c, pair) = await StartAsync( rotations: 10 );
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        a.ApplicationIdentityService.Remotes.ShouldNotContain( r => r.FullName.Path == cName, "No channel from the sender to C." );

        // C rotated 10 times since its anchor: its events from the anchor come in one fetch (the window).
        (await CheckAsync( a, cName, "Keys", Sign( c ) )).ShouldBe( SignatureVerdict.Valid );
        var keys = a.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( cName ).ShouldNotBeNull();
        keys.Head.ShouldNotBeNull().Seq.ShouldBe( 10 );

        // C rotates again: the next fetch is too early (at most one every 5 seconds per party), then it catches up from
        // the head held.
        c.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue();
        var signature = Sign( c );
        (await CheckAsync( a, cName, "Keys", signature )).ShouldBe( SignatureVerdict.UnknownIssuer );
        await Task.Delay( AnchoredKeyDirectory.MinFetchInterval );
        (await CheckAsync( a, cName, "Keys", signature )).ShouldBe( SignatureVerdict.Valid );
        keys.Head!.Seq.ShouldBe( 11 );
    }

    [Test]
    public async Task events_that_dont_match_the_anchor_are_refused_Async()
    {
        // The digest of the anchor is not the one of C: whatever comes back along the route, it is checked, never believed.
        var (a, b, c, pair) = await StartAsync( anchor: cp => $"{cp.Seq}:{new string( '0', 64 )}" );
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await CheckAsync( a, cName, "Keys", Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( l => l.StartsWith( $"The key events received for '{cName}' don't match its trust anchor" ) );
        }
        a.ApplicationIdentityService.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( cName ).ShouldNotBeNull().Head.ShouldBeNull();
    }

    [Test]
    public async Task the_route_must_lead_to_the_anchored_party_Async()
    {
        var (a, b, c, pair) = await StartAsync();
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        string bName = b.ApplicationIdentityService.FullName.Path;
        (await WaitForRouteAsync( a.ApplicationIdentityService, "Routed" )).ShouldBeTrue();
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            // The "Routed" route is hosted by the listener, not by C.
            (await CheckAsync( a, cName, "Routed", Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( $"The route 'Routed' of '{a.ApplicationIdentityService.FullName}' leads to '{bName}', not to '{cName}': its key events can't be fetched along it." );
        }
    }

    [Test]
    public async Task without_a_route_the_signature_is_refused_Async()
    {
        var (a, b, c, pair) = await StartAsync();
        await using var _ = c;
        await using var __ = pair;
        string cName = c.ApplicationIdentityService.FullName.Path;
        using( TestHelper.Monitor.CollectTexts( out var logs ) )
        {
            (await CheckAsync( a, cName, "NoSuchRoute", Sign( c ) )).ShouldBe( SignatureVerdict.UnknownIssuer );
            logs.ShouldContain( $"'{a.ApplicationIdentityService.FullName}' has no route 'NoSuchRoute': the key events of '{cName}' can't be fetched." );
        }
        // A party that is not anchored is never looked up.
        (await CheckAsync( a, b.ApplicationIdentityService.FullName.Path, "Keys", Sign( b ) )).ShouldBe( SignatureVerdict.Refused );
    }
}
