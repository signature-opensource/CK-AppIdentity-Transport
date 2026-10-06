using System.IO;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;
using CK.Testing.AppIdentity.TransportLayer;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// A thief holding a party's CURRENT identity key must not be able to move a remote's pin onto a key
/// of its own. This is the scenario of §1 of <c>.wip/DESIGN-key-pre-rotation.md</c>, and the reason
/// pre-rotation exists.
/// <para>
/// Today a rotation is authorized by the key being rotated away: the pinned key's signature over a
/// list that names a new key first is all it takes. So a stolen key is not only an impersonation,
/// it is a takeover — the remote moves its pin to the thief's key, persists it, and from then on
/// the legitimate party is the one refused.
/// </para>
/// </summary>
[TestFixture]
public class KeyTakeoverTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    [Test, CancelAfter( 30000 )]
    [Ignore( "Reproduces the takeover of DESIGN-key-pre-rotation §1: fails until pre-rotation lands. " +
             "Verified failing on 2026-10-06 against the two-key list protocol: the pin moved to the thief's key." )]
    public async Task a_thief_holding_the_current_key_cannot_move_the_pin_Async( CancellationToken token )
    {
        const string remote = "$AdvTakeover";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        // The legitimate key, and the thief's own key: newer, so that it is presented as the current one.
        using var stolenKey = PeerIdentity.Create( DateTime.UtcNow.AddMinutes( -2 ) );
        using var thiefKey = PeerIdentity.Create( DateTime.UtcNow.AddMinutes( -1 ) );

        // AutoTrustKey only matters for connection 1, where it lets the legitimate key be adopted. The
        // takeover on connection 2 goes through the "trusted key found" path, which does not consult
        // AutoTrustKey at all: Never would behave exactly the same once a key is pinned.
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TakeoverVictim";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        // --- Connection 1: the legitimate party establishes trust in its key. ---
        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, new[] { stolenKey } ), token );
            var final = await c1.ReadFrameAsync( token );
            final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "Baseline must succeed first." );
        }
        File.ReadAllBytes( PeerStore.FindTrustedIdentityFile( $"Test/{remote}" )! )
            .ShouldBe( stolenKey.SubjectPublicKeyInfo, "Connection 1 must have pinned the legitimate key." );

        // --- Connection 2: the thief, holding the stolen key, presents its own key as the current one
        // and signs with both - exactly the shape of a legitimate rotation. ---
        await using var c2 = await peer.AcceptAsync( token );
        var initial2 = await c2.ReadInitialMessageAsync( token );
        await c2.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial2, _systemClock.UtcNow, new[] { thiefKey, stolenKey } ), token );
        // Whatever the initiator answers, give it the time to apply what it read.
        await ReadFrameOrNullAsync( c2, token );

        // The connection itself may succeed: the stolen key IS the pinned key, and impersonating the
        // party until it rotates is what holding its current key means. What must not happen is the
        // pin moving: that is the takeover, and it outlives the connection.
        var pinned = PeerStore.FindTrustedIdentityFile( $"Test/{remote}" );
        pinned.ShouldNotBeNull();
        File.ReadAllBytes( pinned! ).ShouldBe( stolenKey.SubjectPublicKeyInfo,
            "The pin moved to a key chosen by whoever held the current key: a stolen key is a takeover, " +
            "and the legitimate party is now locked out." );
    }

    static async Task<PeerWire.Frame2?> ReadFrameOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try
        {
            return await c.ReadFrameAsync( token );
        }
        catch( EndOfStreamException )
        {
            return null;
        }
        catch( IOException )
        {
            return null;
        }
    }
}
