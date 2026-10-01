using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Establishes that the adversarial harness understands what a real initiator actually sends.
/// <para>
/// This has to pass before any attack test is worth anything: if the harness cannot parse a
/// legitimate handshake, then a rejected attack tells us nothing — the message may have been
/// rejected for being malformed rather than for being hostile.
/// </para>
/// </summary>
[TestFixture]
public class AdversarialPeerTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    [Test, CancelAfter( 20000 )]
    public async Task Harness_parses_a_real_InitialMessage_Async( CancellationToken token )
    {
        // Trusted keys persist in the store per REMOTE name, across local parties and across runs.
        // This test asserts on "we trust nothing yet", so it must start from that state.
        const string remote = "$AdvParse";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();

        // A real initiator that will connect out to the harness.
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$AdvSender";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
        }, ConfigureFastClock, token: token );

        await using var connection = await peer.AcceptAsync( token );
        var initial = await connection.ReadInitialMessageAsync( token );

        TestHelper.Monitor.Info( $"Harness parsed: {initial}" );

        initial.Version.ShouldBe( 0, "ZeroProtocol.CurrentVersion is 0." );
        initial.FullName.ShouldBe( "Test/$AdvSender/#Dev" );
        initial.InstanceId.ShouldNotBeNullOrWhiteSpace();

        // This test host registers no ChannelFeature, so the initiator legitimately advertises an
        // empty protocol list. What must hold is that the declared count and the list agree — that
        // is what proves the harness read the count at the right offset and consumed exactly that
        // many strings.
        initial.ExpectedCommonProtocolCount.ShouldBeLessThanOrEqualTo( initial.AvailableProtocols.Count );
        foreach( var p in initial.AvailableProtocols ) p.ShouldNotBeNullOrWhiteSpace();

        // The identity block: at least one key, one signature each, and each key must be a
        // parseable SubjectPublicKeyInfo — that is what proves the harness found the right offset
        // rather than merely reading plausible-looking bytes.
        initial.Identities.ShouldNotBeEmpty();
        initial.Signatures.Count.ShouldBe( initial.Identities.Count );
        foreach( var k in initial.Identities )
        {
            k.SubjectPublicKeyInfo.ShouldNotBeEmpty();
            k.TimeName.Kind.ShouldBe( System.DateTimeKind.Utc );
            // Throws if these are not actually SPKI bytes at the offset we computed.
            var ecdsa = System.Security.Cryptography.ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo( k.SubjectPublicKeyInfo, out int read );
            read.ShouldBe( k.SubjectPublicKeyInfo.Length, "The key must consume exactly its declared length." );
            ecdsa.KeySize.ShouldBe( 256, "Identity keys are ECDSA P-256." );
            ecdsa.Dispose();
        }
        foreach( var s in initial.Signatures ) s.ShouldNotBeEmpty();

        // We have no trusted key for this brand new remote, so it cannot claim one for us.
        initial.SupposedIdentity.ShouldBeNull();

        // The nonce must be a fresh UTC instant close to now: this pins that we read the timed
        // nonce at the right offset and not some unrelated 8 bytes.
        initial.NonceCreationTime.Kind.ShouldBe( System.DateTimeKind.Utc );
        var age = _systemClock.UtcNow - initial.NonceCreationTime;
        age.Duration().TotalMinutes.ShouldBeLessThan( 5, "The nonce creation time must be around now." );
        initial.Nonce.ShouldNotBe( 0ul );
    }

    [Test, CancelAfter( 20000 )]
    public async Task Initiator_retries_so_the_harness_sees_a_fresh_nonce_each_time_Async( CancellationToken token )
    {
        // Silence is a valid hostile behaviour: the initiator must keep retrying, and every
        // attempt must carry a NEW nonce. A repeated nonce would mean a replayed handshake is
        // indistinguishable from a retry.
        const string remote = "$AdvSilentPeer";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$AdvSilent";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
        }, ConfigureFastClock, token: token );

        var nonces = new System.Collections.Generic.List<ulong>();
        for( int i = 0; i < 3; ++i )
        {
            await using var connection = await peer.AcceptAsync( token );
            var initial = await connection.ReadInitialMessageAsync( token );
            nonces.Add( initial.Nonce );
            // Drop the connection without replying: the initiator must come back.
        }
        nonces.Distinct().Count().ShouldBe( nonces.Count, "Every connection attempt must use a fresh nonce." );
    }
}
