using CK.AppIdentity.TransportLayer.Tests.Adversarial;
using CK.Core;
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
/// The harness's legitimate-handshake baseline.
/// <para>
/// This is the gate for every attack test that follows. If the harness cannot make a real
/// initiator <em>accept</em> it, then an attack the initiator rejects proves nothing — the
/// rejection may be the harness being wrong rather than the initiator being right. Only once the
/// same code path succeeds with the correct key does swapping in a wrong key become evidence.
/// </para>
/// </summary>
[TestFixture]
public class AdversarialHandshakeTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    [Test, CancelAfter( 30000 )]
    public async Task Harness_completes_a_legitimate_handshake_Async( CancellationToken token )
    {
        // The trusted key is stored per REMOTE name and shared across local parties and across
        // runs, so each test owns its remote name and starts from "we trust nothing".
        const string remote = "$AdvOk";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();

        // AutoTrustKey=Once: the initiator has no trusted key for this remote yet, so it adopts
        // the first one presented. That is what lets the harness be accepted at all.
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$HandshakeOk";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var connection = await peer.AcceptAsync( token );
        var initial = await connection.ReadInitialMessageAsync( token );
        TestHelper.Monitor.Info( $"Harness received: {initial}" );

        // Accept exactly the protocols the initiator offered: the initiator checks that all of its
        // BestRegisteredProtocols are satisfied.
        var reply = PeerMessages.AcceptedProtocols( initial.Nonce,
                                                    initialClockOffset: TimeSpan.Zero,
                                                    now: _systemClock.UtcNow,
                                                    protocolFullNames: initial.AvailableProtocols,
                                                    signWith: new[] { peerKey } );
        await connection.SendZeroFrameAsync( reply, token );

        // The initiator must now verify us and answer FinalSuccess.
        var final = await connection.ReadFrameAsync( token );
        final.IsZeroProtocol.ShouldBeTrue();
        final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage,
                                      "A verified AcceptedProtocols must be answered with FinalSuccess. " +
                                      "Anything else means the harness built a message the initiator could not accept." );

        // And the connection must come up.
        await feature.ReadyTask.WaitAsync( token );
        feature.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Harness_signing_with_an_unknown_key_is_refused_once_a_key_is_trusted_Async( CancellationToken token )
    {
        // Same code path as the baseline above, one parameter changed: the signing key.
        // First connection establishes trust in peerKey (AutoTrustKey=Once).
        // Second connection presents evilKey instead — the initiator already has a trusted key, and
        // "Once" does not adopt a second one, so this is a SelfAsserted signature and must NOT be
        // accepted. This is finding C2's shape.
        const string remote = "$AdvEvil";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();
        using var evilKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$HandshakeEvil";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        // --- Connection 1: legitimate, establishes trust. ---
        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial.Nonce,
                                                                        TimeSpan.Zero,
                                                                        _systemClock.UtcNow,
                                                                        initial.AvailableProtocols,
                                                                        new[] { peerKey } ), token );
            var final = await c1.ReadFrameAsync( token );
            final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "Baseline must succeed first." );
        }

        // --- Connection 2: the impostor. ---
        await using var c2 = await peer.AcceptAsync( token );
        var initial2 = await c2.ReadInitialMessageAsync( token );

        // The initiator now holds a trusted key and tells us which one it expects.
        initial2.SupposedIdentity.ShouldNotBeNull( "The initiator should now claim a trusted key for us." );
        initial2.SupposedIdentity!.SubjectPublicKeyInfo.ShouldBe( peerKey.SubjectPublicKeyInfo,
                                                                  "It must be the key adopted on the first connection." );

        await c2.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial2.Nonce,
                                                                     TimeSpan.Zero,
                                                                     _systemClock.UtcNow,
                                                                     initial2.AvailableProtocols,
                                                                     new[] { evilKey } ), token );

        // The initiator must not send FinalSuccess to a key it does not trust.
        var answer = await ReadFrameOrNullAsync( c2, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                "An AcceptedProtocols signed by an untrusted key must never be answered with FinalSuccess: " +
                "'the signature verifies' is not 'this is our remote' (finding C2)." );
        }
    }

    /// <summary>
    /// Reads a frame, returning null when the peer closes the connection instead of replying —
    /// a perfectly valid way for the initiator to reject us.
    /// </summary>
    static async Task<PeerWire.Frame2?> ReadFrameOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try
        {
            return await c.ReadFrameAsync( token );
        }
        catch( System.IO.EndOfStreamException )
        {
            return null;
        }
        catch( System.IO.IOException )
        {
            return null;
        }
    }
}
