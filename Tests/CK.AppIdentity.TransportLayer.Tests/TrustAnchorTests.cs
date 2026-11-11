using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
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
/// The anchored remotes ("Local:TrustAnchors:{FullName}"): a remote whose full name has an anchor is verified from it at
/// each handshake, never trusted on first use nor approved by an operator; a mismatch is a peering issue of its own.
/// </summary>
[TestFixture]
public class TrustAnchorTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services ) => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    // A fresh identity for both parties, and nothing pinned between them.
    static void Reset( params string[] names )
    {
        foreach( var n in names )
        {
            IdentityStoreHelper.ClearKeys( n );
            PeerStore.ClearRemoteTrust( $"Test/${n}" );
        }
    }

    // Starts a party alone: its keys are created (or loaded), its full name and its checkpoint are returned.
    async Task<(string FullName, KeyCheckpoint Checkpoint)> CheckpointOfAsync( string name, CancellationToken token )
    {
        await using var s = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = $"Test/${name}", ConfigureFastClock, token: token );
        return (s.FullName.Path, s.GetRequiredFeature<ILocalKeys>().Checkpoint);
    }

    Task<ApplicationIdentityService> ListenerAsync( string name, string initiator, Action<MutableConfigurationSection> configure, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = $"${initiator}";
            configure( c );
        }, ConfigureFastClock, token: token );

    Task<ApplicationIdentityService> InitiatorAsync( string name, string listener, Action<MutableConfigurationSection> configure, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = $"${listener}";
            c["Parties:0:Address"] = "tcp:127.0.0.1:37120";
            configure( c );
        }, ConfigureFastClock, token: token );

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

    static string? Connected( ApplicationIdentityService s )
        => s.Remotes.Single().GetRequiredFeature<TransportFeature>().ConnectionAvailability == ConnectionAvailability.Connected ? "connected" : null;

    static PeeringIssue? Issue( ApplicationIdentityService s, PeeringIssueKind kind )
        => s.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().FirstOrDefault( i => i.Kind == kind );

    [Test, CancelAfter( 120000 )]
    public async Task anchored_parties_connect_without_trust_on_first_use_nor_approval_Async( CancellationToken token )
    {
        Reset( "AnchL1", "AnchI1" );
        var l = await CheckpointOfAsync( "AnchL1", token );
        var i = await CheckpointOfAsync( "AnchI1", token );
        // Both sides are "Never": only the anchors can create the pins.
        await using var listener = await ListenerAsync( "AnchL1", "AnchI1", c => c[$"Local:TrustAnchors:{i.FullName}"] = i.Checkpoint.ToString(), token );
        await using var initiator = await InitiatorAsync( "AnchI1", "AnchL1", c => c[$"Local:TrustAnchors:{l.FullName}"] = l.Checkpoint.ToString(), token );

        (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull( "Each one verified the other from its anchor." );
        listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent!.Seq.ShouldBe( i.Checkpoint.Seq );
        listener.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().ShouldBeEmpty();
    }

    [Test, CancelAfter( 120000 )]
    public async Task a_listener_whose_anchor_does_not_match_refuses_the_initiator_without_approval_Async( CancellationToken token )
    {
        Reset( "AnchL2", "AnchI2" );
        var l = await CheckpointOfAsync( "AnchL2", token );
        var i = await CheckpointOfAsync( "AnchI2", token );
        // The anchor of the initiator is the listener's own checkpoint: its digest covers another full name.
        await using var listener = await ListenerAsync( "AnchL2", "AnchI2", c => c[$"Local:TrustAnchors:{i.FullName}"] = l.Checkpoint.ToString(), token );
        await using var initiator = await InitiatorAsync( "AnchI2", "AnchL2", c => c["Parties:0:AutoTrustKey"] = "Once", token );

        var held = await WaitForAsync( () => Issue( listener, PeeringIssueKind.AnchorMismatch ), 40, token );
        held.ShouldNotBeNull( "The listener can't verify the initiator from its anchor." );
        held.ApprovalCode.ShouldBeNull( "No approval applies to an anchored remote." );
        held.EnlistUrl.ShouldBeNull();
        listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.AnchorRefusal.ShouldBe( KeyChainVerdict.AnchorMismatch );
        (await WaitForAsync( () => Issue( initiator, PeeringIssueKind.RemoteAnchorMismatch ), 40, token ))
            .ShouldNotBeNull( "The initiator learns that its remote must update its anchor." );
        Connected( initiator ).ShouldBeNull();
    }

    [Test, CancelAfter( 120000 )]
    public async Task an_initiator_whose_anchor_does_not_match_refuses_the_listener_Async( CancellationToken token )
    {
        Reset( "AnchL3", "AnchI3" );
        var l = await CheckpointOfAsync( "AnchL3", token );
        var i = await CheckpointOfAsync( "AnchI3", token );
        await using var listener = await ListenerAsync( "AnchL3", "AnchI3", c => c["Parties:0:AutoTrustKey"] = "Once", token );
        await using var initiator = await InitiatorAsync( "AnchI3", "AnchL3", c => c[$"Local:TrustAnchors:{l.FullName}"] = i.Checkpoint.ToString(), token );

        (await WaitForAsync( () => Issue( initiator, PeeringIssueKind.AnchorMismatch ), 40, token ))
            .ShouldNotBeNull( "The initiator can't verify the listener from its anchor." );
        Connected( initiator ).ShouldBeNull();
    }

    [Test, CancelAfter( 120000 )]
    public async Task a_pin_that_contradicts_the_anchor_is_replaced_Async( CancellationToken token )
    {
        Reset( "AnchL4", "AnchI4" );
        // First, the listener trusts the initiator on first use.
        await using( var listener = await ListenerAsync( "AnchL4", "AnchI4", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        await using( var initiator = await InitiatorAsync( "AnchI4", "AnchL4", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        {
            (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull();
        }
        // The initiator incepts again (a new identity under the same name): the pin of the listener is now wrong.
        IdentityStoreHelper.ClearKeys( "AnchI4" );
        var i = await CheckpointOfAsync( "AnchI4", token );
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 5000 );
        // The listener is told the new identity by an anchor (its "Once" is ignored, with a warning).
        await using( var listener = await ListenerAsync( "AnchL4", "AnchI4", c =>
                                                         {
                                                             c["Parties:0:AutoTrustKey"] = "Once";
                                                             c[$"Local:TrustAnchors:{i.FullName}"] = i.Checkpoint.ToString();
                                                         }, token ) )
        await using( var initiator = await InitiatorAsync( "AnchI4", "AnchL4", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        {
            (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull( "The anchor replaced the wrong pin." );
            i.Checkpoint.Matches( i.FullName, listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent! ).ShouldBeTrue();
        }
        var texts = logs.ExtractCurrentTexts();
        texts.ShouldContain( t => t.Contains( "contradicts its trust anchor" ) );
        texts.ShouldContain( t => t.Contains( "is anchored: its AutoTrustKey \"Once\" is ignored" ) );
    }

    // Starts a party alone and rotates its identity key: its log grows by count events.
    async Task RotateAsync( string name, int count, CancellationToken token )
    {
        await using var s = await TestHelper.CreateApplicationServiceAsync( c => c["FullName"] = $"Test/${name}", ConfigureFastClock, token: token );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        for( int i = 0; i < count; ++i ) keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
    }

    [Test, CancelAfter( 120000 )]
    public async Task an_initiator_anchored_at_an_old_point_of_the_listener_gets_its_events_from_there_Async( CancellationToken token )
    {
        Reset( "AnchL5", "AnchI5" );
        var l = await CheckpointOfAsync( "AnchL5", token );
        // The listener rotates 10 times: its usual 8 events don't reach its inception anymore.
        await RotateAsync( "AnchL5", 10, token );
        await using var listener = await ListenerAsync( "AnchL5", "AnchI5", c => c["Parties:0:AutoTrustKey"] = "Once", token );
        await using var initiator = await InitiatorAsync( "AnchI5", "AnchL5", c => c[$"Local:TrustAnchors:{l.FullName}"] = l.Checkpoint.ToString(), token );
        (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull( "The listener sent its events from the anchor stated by the initiator." );
        initiator.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent!.Seq.ShouldBe( 10 );
    }

    [Test, CancelAfter( 120000 )]
    public async Task a_listener_anchored_at_an_old_point_of_the_initiator_asks_its_events_from_there_Async( CancellationToken token )
    {
        Reset( "AnchL6", "AnchI6" );
        var i = await CheckpointOfAsync( "AnchI6", token );
        await RotateAsync( "AnchI6", 10, token );
        await using var listener = await ListenerAsync( "AnchL6", "AnchI6", c => c[$"Local:TrustAnchors:{i.FullName}"] = i.Checkpoint.ToString(), token );
        await using var initiator = await InitiatorAsync( "AnchI6", "AnchL6", c => c["Parties:0:AutoTrustKey"] = "Once", token );
        (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull( "EventsRequired: the initiator retried with its events from the anchor." );
        listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent!.Seq.ShouldBe( 10 );
        initiator.GetRequiredFeature<TransportManagerFeature>().GetPeeringIssues().ShouldBeEmpty( "Not an issue: a step of the handshake." );
    }

    [Test, CancelAfter( 120000 )]
    public async Task a_pin_far_behind_catches_up_without_approval_Async( CancellationToken token )
    {
        Reset( "AnchL7", "AnchI7" );
        await using( var listener = await ListenerAsync( "AnchL7", "AnchI7", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        await using( var initiator = await InitiatorAsync( "AnchI7", "AnchL7", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        {
            (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull();
        }
        // The initiator rotates 10 times while the listener is away: more than a usual tail.
        await RotateAsync( "AnchI7", 10, token );
        await using( var listener = await ListenerAsync( "AnchL7", "AnchI7", c => { }, token ) )
        await using( var initiator = await InitiatorAsync( "AnchI7", "AnchL7", c => c["Parties:0:AutoTrustKey"] = "Once", token ) )
        {
            (await WaitForAsync( () => Connected( initiator ), 40, token )).ShouldNotBeNull( "The pin caught up from the events sent from it." );
            listener.Remotes.Single().GetRequiredFeature<TransportFeature>().RemoteKeys.TrustedEvent!.Seq.ShouldBe( 10 );
        }
    }

    [Test, CancelAfter( 120000 )]
    public async Task an_anchor_beyond_the_window_must_be_updated_Async( CancellationToken token )
    {
        Reset( "AnchL8", "AnchI8" );
        var i = await CheckpointOfAsync( "AnchI8", token );
        await RotateAsync( "AnchI8", KeyEventChain.MaxEventWindow + 1, token );
        await using var listener = await ListenerAsync( "AnchL8", "AnchI8", c => c[$"Local:TrustAnchors:{i.FullName}"] = i.Checkpoint.ToString(), token );
        await using var initiator = await InitiatorAsync( "AnchI8", "AnchL8", c => c["Parties:0:AutoTrustKey"] = "Once", token );
        (await WaitForAsync( () => Issue( listener, PeeringIssueKind.AnchorMismatch ), 40, token )).ShouldNotBeNull( "The anchor is too old to be reached." );
        (await WaitForAsync( () => Issue( initiator, PeeringIssueKind.RemoteAnchorMismatch ), 40, token )).ShouldNotBeNull();
        Connected( initiator ).ShouldBeNull();
    }
}
