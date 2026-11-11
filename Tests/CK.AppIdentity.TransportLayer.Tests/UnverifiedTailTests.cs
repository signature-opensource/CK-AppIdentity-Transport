using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// What a remote presents is verified before it changes anything: a forged event never clears a pin nor raises a sticky
/// refusal (TM-1, TM-5), and an anchored remote is held to its pin like any other one once it verified from its anchor
/// (KM-1, KM-6). The key directory honors the revocations (KM-2).
/// </summary>
[TestFixture]
public class UnverifiedTailTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static string RemoteFullName( string name ) => $"Test/${name}Peer/#Dev";

    Task<ApplicationIdentityService> CreateAsync( string name, KeyCheckpoint? anchor, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = $"${name}Peer";
            if( anchor != null ) c[$"Local:TrustAnchors:{RemoteFullName( name )}"] = anchor.ToString();
        }, ConfigureFastClock, token: token );

    static IRemoteKeys KeysOf( ApplicationIdentityService s ) => s.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>();

    // The same event with a broken signature: what anyone can write.
    static KeyEvent Forge( KeyEvent e )
    {
        var bytes = e.Encoded.ToArray();
        bytes[^1] ^= 0xFF;
        return KeyEvent.Read( bytes );
    }

    static Task RevokeAsync( ApplicationIdentityService s, string fullName, KeyEvent e )
        => s.GetRequiredFeature<ILocalKeys>()
            .SetRevocationsAsync( TestHelper.Monitor, [new RevocationEntry( fullName, e.GetIdentity( fullName ).Span, DateTime.UtcNow, nameBanned: false )] );

    [Test, CancelAfter( 60000 )]
    public async Task a_forged_event_naming_a_revoked_identity_changes_nothing_Async( CancellationToken token )
    {
        const string name = "TM1Forge";
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var fullName = RemoteFullName( name );
        await using var service = await CreateAsync( name, null, token );
        var keys = KeysOf( service );

        using var peer = PeerIdentity.Create( fullName );
        keys.SetTrustedIdentity( TestHelper.Monitor, peer.Head ).ShouldBeTrue();
        // Another log of the same name, revoked (the party incepted again after it).
        using var revoked = PeerIdentity.Create( fullName );
        revoked.Rotate();
        await RevokeAsync( service, fullName, revoked.Head );

        // Anyone can write the revoked identity in an event: it doesn't verify, it is only invalid.
        keys.ApplyTail( TestHelper.Monitor, [Forge( revoked.Head )] ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
        keys.TrustedEvent.ShouldBe( peer.Head, "A forged event must not clear the pin." );
        keys.IsRevoked.ShouldBeFalse();
        keys.Refusal.ShouldBeNull();

        // The revoked log itself is refused, but it is not the pinned one: the pin stays, and the live connection of the
        // pinned remote must not be cut.
        keys.ApplyTail( TestHelper.Monitor, revoked.Events ).Verdict.ShouldBe( KeyChainVerdict.Revoked );
        keys.TrustedEvent.ShouldBe( peer.Head, "Another log presented under the name doesn't clear the pin." );
        keys.IsRevoked.ShouldBeFalse( "Only the revocation of the pinned identity revokes the remote." );

        // The revocation of the pinned identity does.
        await RevokeAsync( service, fullName, peer.Head );
        keys.TrustedEvent.ShouldBeNull();
        keys.IsRevoked.ShouldBeTrue();
    }

    [Test, CancelAfter( 60000 )]
    public async Task garbage_presented_for_an_anchored_remote_raises_no_refusal_Async( CancellationToken token )
    {
        const string name = "TM5Garbage";
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var fullName = RemoteFullName( name );
        using var peer = PeerIdentity.Create( fullName );
        await using var service = await CreateAsync( name, KeyCheckpoint.Of( fullName, peer.Head ), token );
        var keys = KeysOf( service );
        using var other = PeerIdentity.Create( fullName );

        keys.ApplyTail( TestHelper.Monitor, [Forge( other.Head )] ).Verdict.ShouldBe( KeyChainVerdict.Invalid );
        keys.Refusal.ShouldBeNull( "Bytes that don't verify say nothing about the anchored remote." );

        // A valid log that doesn't match the anchor is a real mismatch.
        keys.ApplyTail( TestHelper.Monitor, other.Events ).Verdict.ShouldBe( KeyChainVerdict.AnchorMismatch );
        keys.Refusal.ShouldBe( KeyChainVerdict.AnchorMismatch );

        // The anchored remote itself.
        keys.ApplyTail( TestHelper.Monitor, peer.Events ).Verdict.ShouldBe( KeyChainVerdict.UpToDate );
        keys.Refusal.ShouldBeNull();
        keys.TrustedEvent.ShouldBe( peer.Head );
    }

    [Test, CancelAfter( 60000 )]
    public async Task an_anchored_pin_refuses_a_fork_and_an_older_head_Async( CancellationToken token )
    {
        const string name = "KM1Fork";
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var fullName = RemoteFullName( name );
        using var peer = PeerIdentity.Create( fullName );
        // The anchor is the inception (set at deployment); the remote rotated since.
        await using var service = await CreateAsync( name, KeyCheckpoint.Of( fullName, peer.Head ), token );
        var keys = KeysOf( service );
        for( int i = 0; i < 3; ++i ) peer.Rotate();
        keys.ApplyTail( TestHelper.Monitor, peer.Events ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        var pinned = peer.Head;
        keys.TrustedEvent.ShouldBe( pinned );

        // (a) A thief of the current key (#3) forks: another #3 with the same key, that commits to its own next key.
        using var thiefKey = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        using var afterKey = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var now = DateTime.UtcNow;
        var fork3 = KeyEvent.Create( fullName, 3, now, peer.CurrentKey, KeyEvent.ComputeCommit( thiefKey.ExportSubjectPublicKeyInfo() ), peer.Events[2] );
        var fork4 = KeyEvent.Create( fullName, 4, now, thiefKey, KeyEvent.ComputeCommit( afterKey.ExportSubjectPublicKeyInfo() ), fork3 );
        var check = keys.ApplyTail( TestHelper.Monitor, [peer.Events[0], peer.Events[1], peer.Events[2], fork3, fork4] );
        check.Verdict.ShouldBe( KeyChainVerdict.Duplicity, "The fork verifies from the anchor, but not from the pin." );
        keys.TrustedEvent.ShouldBe( pinned );
        service.GetRequiredFeature<ILocalKeys>().Alerts.ShouldContain( a => a.Kind == IdentityAlertKind.RemoteDuplicity && a.Subject == fullName );

        // (b) A holder of the retired key #0 presents only the anchored event.
        keys.ApplyTail( TestHelper.Monitor, [peer.Events[0]] ).Verdict.ShouldBe( KeyChainVerdict.Rollback );
        keys.TrustedEvent.ShouldBe( pinned, "An older head must not move the pin back." );

        // The genuine remote goes on.
        peer.Rotate();
        keys.ApplyTail( TestHelper.Monitor, peer.Events ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        keys.TrustedEvent.ShouldBe( peer.Head );
    }

    [Test, CancelAfter( 60000 )]
    public async Task a_pin_before_the_anchor_with_garbage_in_between_is_replaced_by_the_anchored_head_Async( CancellationToken token )
    {
        const string name = "KM6Garbage";
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var fullName = RemoteFullName( name );
        using var peer = PeerIdentity.Create( fullName );
        for( int i = 0; i < 3; ++i ) peer.Rotate();
        // First pinned at #1 while not anchored...
        await using( var notAnchored = await CreateAsync( name, null, token ) )
        {
            KeysOf( notAnchored ).SetTrustedIdentity( TestHelper.Monitor, peer.Events[1] ).ShouldBeTrue();
        }
        // ...then anchored at #3 by an operator.
        await using var service = await CreateAsync( name, KeyCheckpoint.Of( fullName, peer.Head ), token );
        var keys = KeysOf( service );
        keys.TrustedEvent!.Seq.ShouldBe( 1 );

        // The genuine #1 and #3 with an event of another log at #2: the anchor doesn't cover #2.
        using var other = PeerIdentity.Create( fullName );
        other.Rotate();
        other.Rotate();
        var check = keys.ApplyTail( TestHelper.Monitor, [peer.Events[1], other.Events[2], peer.Events[3]] );
        check.Verdict.ShouldBe( KeyChainVerdict.UpToDate );
        keys.TrustedEvent.ShouldBe( peer.Head, "The anchor is the authority: its verified head replaces the pin." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task the_key_directory_honors_the_revocations_Async( CancellationToken token )
    {
        const string name = "KM2Directory";
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        // An anchored party that is not a remote: an entry of the key directory.
        var fullName = $"Test/${name}Other/#Dev";
        using var other = PeerIdentity.Create( fullName );
        await using var service = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c[$"Local:TrustAnchors:{fullName}"] = KeyCheckpoint.Of( fullName, other.Head ).ToString();
        }, ConfigureFastClock, token: token );
        var directory = service.GetRequiredFeature<ILocalKeys>().FindAnchoredKeys( fullName );
        directory.ShouldNotBeNull();
        other.Rotate();
        directory.ApplyEvents( TestHelper.Monitor, other.Events ).Verdict.ShouldBe( KeyChainVerdict.Advanced );
        directory.Head.ShouldBe( other.Head );

        await RevokeAsync( service, fullName, other.Head );
        directory.Head.ShouldBeNull( "What is held of a revoked identity is forgotten." );
        directory.ApplyEvents( TestHelper.Monitor, other.Events ).Verdict.ShouldBe( KeyChainVerdict.Revoked );
        directory.Head.ShouldBeNull();
    }
}
