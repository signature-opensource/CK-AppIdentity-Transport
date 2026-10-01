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
/// Finding C2: "the signature verifies" is not "this is our remote".
/// <para>
/// When our trusted key is absent from the keys a message presents, a verifier that falls back to
/// the key the sender supplied <em>in that same message</em> succeeds for anybody. A reader acting
/// on that result is authenticating nobody. These tests drive the audit's failure scenarios against
/// the real stack.
/// </para>
/// <para>
/// Note that <c>TryReadAcceptedProtocolsMessage</c> already gated on the trusted key before the
/// fix; the readers that did not were <c>ReadOffRemoteMessage</c>,
/// <c>ReadEvictionDisallowedMessage</c> and <c>TryReadMissingProtocolsMessage</c>. The OffRemote
/// case below is therefore the one that actually exercises the fix, and it is the audit's most
/// damaging scenario: one packet, no key material, remote off for good.
/// </para>
/// </summary>
[TestFixture]
public class C2SelfAssertedSignatureTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    [Test, CancelAfter( 30000 )]
    public async Task A_self_asserted_OffRemote_must_not_switch_the_remote_off_Async( CancellationToken token )
    {
        const string remote = "$AdvOff";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var goodKey = PeerIdentity.Create();
        using var evilKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$C2Off";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        // --- 1. Legitimate handshake so the initiator pins goodKey. ---
        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { goodKey } ), token );
            (await c1.ReadFrameAsync( token )).Discriminator
                .ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "The baseline handshake must succeed first." );
            await feature.ReadyTask.WaitAsync( token );
        }
        feature.IsOff.ShouldBeFalse( "Sanity: the remote is on after a legitimate handshake." );

        // --- 2. The attack. The initiator reconnects; we answer with a permanent switch-off,
        //        signed by a key it has never seen. Util.UtcMaxValue means "never coming back". ---
        await using( var c2 = await peer.AcceptAsync( token ) )
        {
            var initial2 = await c2.ReadInitialMessageAsync( token );
            initial2.SupposedIdentity.ShouldNotBeNull( "The initiator must now pin a key for this remote." );
            initial2.SupposedIdentity!.SubjectPublicKeyInfo.ShouldBe( goodKey.SubjectPublicKeyInfo );

            var attack = PeerMessages.OffRemote( initial2.Nonce,
                                                 clockOffset: TimeSpan.Zero,
                                                 reason: "Gone for good.",
                                                 expectedAvailableTime: Util.UtcMaxValue,
                                                 signWith: new[] { evilKey } );
            await c2.SendZeroFrameAsync( attack, token );
        }

        // --- 3. The attack must have changed nothing. ---
        // An accepted OffRemote(UtcMaxValue) switches the remote off permanently: it would stop
        // reconnecting until someone calls SwitchOn(). So the decisive evidence is that the
        // initiator comes back.
        using var reconnect = new CancellationTokenSource( TimeSpan.FromSeconds( 10 ) );
        using var linked = CancellationTokenSource.CreateLinkedTokenSource( reconnect.Token, token );

        PeerConnection? c3 = null;
        try
        {
            c3 = await peer.AcceptAsync( linked.Token );
        }
        catch( OperationCanceledException )
        {
            // Fall through to the assertion below, which reports the real problem.
        }

        feature.IsOff.ShouldBeFalse(
            "A DNegoOffRemote signed by a key we do not trust must be ignored. If this fails, one " +
            "unauthenticated packet takes the remote down permanently (finding C2, scenario 1)." );
        c3.ShouldNotBeNull(
            "The initiator must keep reconnecting after rejecting the forged switch-off." );
        await c3!.DisposeAsync();
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_trusted_OffRemote_does_switch_the_remote_off_Async( CancellationToken token )
    {
        // The counterpart of the test above, and the reason it is evidence rather than an accident:
        // the very same message, signed by the key the initiator trusts, MUST be honoured. Without
        // this, "the remote stayed on" could simply mean the harness builds an OffRemote nobody can
        // parse.
        const string remote = "$AdvOffOk";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var goodKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$C2OffOk";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { goodKey } ), token );
            (await c1.ReadFrameAsync( token )).Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage );
            await feature.ReadyTask.WaitAsync( token );
        }

        await using( var c2 = await peer.AcceptAsync( token ) )
        {
            var initial2 = await c2.ReadInitialMessageAsync( token );
            await c2.SendZeroFrameAsync( PeerMessages.OffRemote( initial2.Nonce,
                                                                 TimeSpan.Zero,
                                                                 "Maintenance, not coming back.",
                                                                 Util.UtcMaxValue,
                                                                 new[] { goodKey } ), token );
        }

        // The remote must go off — proving the harness's OffRemote is well-formed and understood.
        var deadline = DateTime.UtcNow.AddSeconds( 10 );
        while( !feature.IsOff && DateTime.UtcNow < deadline )
        {
            await Task.Delay( 50, token );
        }
        feature.IsOff.ShouldBeTrue(
            "An OffRemote signed by the TRUSTED key must switch the remote off. If this fails the " +
            "harness is not producing a message the initiator accepts, and the negative test above " +
            "would prove nothing." );
    }
}
