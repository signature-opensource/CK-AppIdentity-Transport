using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The key checkpoint of a party (<see cref="ILocalKeys.Checkpoint"/>) and the trust anchors of its configuration
/// (<see cref="ILocalKeys.TrustAnchors"/>, "Local:TrustAnchors:{FullName}").
/// </summary>
[TestFixture]
public class KeyCheckpointTests
{
    const string Hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    [Test]
    public void a_checkpoint_is_a_sequence_and_a_digest()
    {
        KeyCheckpoint.TryParse( $"3:{Hex}", out var c, out var error ).ShouldBeTrue( error );
        c.Seq.ShouldBe( 3 );
        c.Digest.Length.ShouldBe( KeyCheckpoint.DigestLength );
        c.ToString().ShouldBe( $"3:{Hex}" );
        KeyCheckpoint.TryParse( $" 3:{Hex.ToUpperInvariant()} ", out var upper, out _ ).ShouldBeTrue( "The hex digest is case insensitive." );
        upper.ShouldBe( c );
        upper.ToString().ShouldBe( $"3:{Hex}", "Written in lowercase." );

        KeyCheckpoint.TryParse( null, out _, out error ).ShouldBeFalse();
        KeyCheckpoint.TryParse( Hex, out _, out error ).ShouldBeFalse( "No sequence." );
        KeyCheckpoint.TryParse( $"-1:{Hex}", out _, out error ).ShouldBeFalse( "A negative sequence." );
        KeyCheckpoint.TryParse( $"3:{Hex[..^2]}", out _, out error ).ShouldBeFalse( "A short digest." );
        error.ShouldContain( "64 hexadecimal characters" );
        KeyCheckpoint.TryParse( $"3:{Hex[..^2]}zz", out _, out error ).ShouldBeFalse( "Not hexadecimal." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task the_checkpoint_of_a_party_is_its_head_and_follows_its_rotations_Async( CancellationToken token )
    {
        const string partyName = "CheckpointHead";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        string fullName = s.FullName;

        var first = keys.Checkpoint;
        first.Seq.ShouldBe( keys.Seq );
        first.Matches( fullName, keys.State.Head ).ShouldBeTrue();
        first.Matches( "Test/$Other", keys.State.Head ).ShouldBeFalse( "The digest covers the full name." );

        keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
        var second = keys.Checkpoint;
        second.Seq.ShouldBe( first.Seq + 1 );
        second.ShouldNotBe( first );
        // The former checkpoint still names its event: the log is verified from it.
        first.Matches( fullName, keys.State.GetEvent( first.Seq )! ).ShouldBeTrue();
    }

    [Test, CancelAfter( 30000 )]
    public async Task the_trust_anchors_are_read_from_the_configuration_Async( CancellationToken token )
    {
        const string partyName = "AnchorsReader";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                   configure: c => c[$"Local:TrustAnchors:Test/$Center/#Dev"] = $"7:{Hex}" );
        var anchors = s.GetRequiredFeature<ILocalKeys>().TrustAnchors;
        anchors.Count.ShouldBe( 1 );
        anchors["Test/$Center/#Dev"].ToString().ShouldBe( $"7:{Hex}" );
    }

    [Test, CancelAfter( 30000 )]
    public async Task an_invalid_trust_anchor_fails_the_setup_Async( CancellationToken token )
    {
        const string partyName = "AnchorsInvalid";
        IdentityStoreHelper.ClearKeys( partyName );
        // The errors are logged by the agent of the party: the texts are collected from the GrandOutput.
        using var logs = CK.Monitoring.GrandOutput.Default!.CreateMemoryCollector( 5000 );
        // Never ignored: the anchored party would be trusted on first use instead of verified.
        await Should.ThrowAsync<Exception>( () => IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                                    configure: c => c["Local:TrustAnchors:Test/$Center/#Dev"] = "not-a-checkpoint" ) );
        // A party doesn't anchor itself.
        await Should.ThrowAsync<Exception>( () => IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                                    configure: c => c[$"Local:TrustAnchors:Test/${partyName}/#Dev"] = $"0:{Hex}" ) );
        // "#Dev" is allowed only in the dev store of a development solution.
        await Should.ThrowAsync<Exception>( () => IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                                    configure: c => c["Local:TrustAnchors:Test/$Center/#Dev"] = "#Dev" ) );
        // The reasons are the exceptions of the failed setups.
        var errors = logs.ExtractCurrentEntries().Select( e => e.Exception?.Message ).Where( m => m != null ).ToList();
        errors.ShouldContain( m => m!.Contains( "Invalid key checkpoint 'not-a-checkpoint'" ) );
        errors.ShouldContain( m => m!.Contains( "a party doesn't anchor itself" ) );
        errors.ShouldContain( m => m!.Contains( "is allowed only in the dev store" ) );
    }
}
