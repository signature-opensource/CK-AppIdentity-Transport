using System.IO;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
/// Before pre-rotation, a rotation was authorized by the key being rotated away: the pinned key's
/// signature over a list that named a new key first was all it took (verified 2026-10-06 against the
/// two-key list protocol: the pin moved to the thief's key). Now the right to rotate belongs to the
/// key the previous event committed to, which the thief does not have.
/// </para>
/// </summary>
[TestFixture]
public class KeyTakeoverTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    Task<ApplicationIdentityService> CreateVictimAsync( string localName, string remote, string address, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = address;
            // AutoTrustKey only matters for connection 1, where it lets the legitimate identity be
            // adopted. What happens next goes through the pinned chain, never through AutoTrustKey.
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

    /// <summary>Connection 1: the legitimate party gets pinned.</summary>
    async Task PinAsync( AdversarialPeer peer, PeerIdentity legitimate, string remote, CancellationToken token )
    {
        await using var c1 = await peer.AcceptAsync( token );
        var initial = await c1.ReadInitialMessageAsync( token );
        await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, legitimate ), token );
        var final = await c1.ReadFrameAsync( token );
        final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "Baseline must succeed first." );
        PeerStore.ReadTrustedIdentity( $"Test/{remote}" )!.Seq.ShouldBe( 0, "Connection 1 must have pinned the inception." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task a_thief_holding_the_current_key_cannot_move_the_pin_Async( CancellationToken token )
    {
        const string remote = "$AdvTakeover";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        var fullName = $"Test/{remote}/#Dev";

        await using var peer = new AdversarialPeer();
        using var legitimate = PeerIdentity.Create( fullName );
        await using var victim = await CreateVictimAsync( "$TakeoverVictim", remote, peer.Address, token );
        await PinAsync( peer, legitimate, remote, token );

        // --- Connection 2: the thief holds the legitimate CURRENT key (key 0) and a key of its own.
        // It writes event 1 revealing its key and signs it with that key, and signs the transcript with
        // it too: every signature verifies. Only the commitment of event 0 - to key 1, which the thief
        // does not have - stands in the way. (Having the stolen key sign the event instead fails even
        // earlier, on the event's own signature: that variant is covered by KeyEventChainTests.) ---
        using var thiefKey = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var forged = ForgeEvent( fullName, 1, revealed: thiefKey, signer: thiefKey,
                                 nextCommit: KeyEvent.ComputeCommit( thiefKey.ExportSubjectPublicKeyInfo() ),
                                 previous: legitimate.Head );
        await using( var c2 = await peer.AcceptAsync( token ) )
        {
            var initial2 = await c2.ReadInitialMessageAsync( token );
            // Its credential is issued by its own key, the one the forged head reveals: everything verifies
            // but the commitment.
            using var thiefCredential = PeerCredential.Issue( thiefKey, fullName );
            var reply = PeerMessages.Build( ( ref FastByteWriter w ) => WriteAcceptedBody( ref w, initial2 ),
                                            new[] { legitimate.Head, forged }, thiefCredential.Encoded, thiefCredential.Key, null );
            await c2.SendZeroFrameAsync( reply, token );
            var answer = await ReadFrameOrNullAsync( c2, token );
            if( answer != null )
            {
                answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                    "A forged rotation must not authenticate anybody." );
            }
        }

        var pinned = PeerStore.ReadTrustedIdentity( $"Test/{remote}" );
        pinned.ShouldNotBeNull();
        pinned.Seq.ShouldBe( 0, "The pin did not move: holding the current key does not give the right to rotate." );
        pinned.Spki.ToArray().ShouldBe( legitimate.SubjectPublicKeyInfo );

        // --- Connection 3: the legitimate party rotates, and the pin follows. ---
        legitimate.Rotate();
        await using var c3 = await peer.AcceptAsync( token );
        var initial3 = await c3.ReadInitialMessageAsync( token );
        await c3.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial3, _systemClock.UtcNow, legitimate ), token );
        (await c3.ReadFrameAsync( token )).Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage );
        PeerStore.ReadTrustedIdentity( $"Test/{remote}" )!.Seq.ShouldBe( 1, "A committed rotation advances the pin." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task once_rotated_the_superseded_key_is_refused_Async( CancellationToken token )
    {
        // What makes a rotation a revocation: after it, the previous key is worth nothing to whoever
        // holds it, even presenting the very tail it was once current with.
        const string remote = "$AdvSuperseded";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        var fullName = $"Test/{remote}/#Dev";

        await using var peer = new AdversarialPeer();
        using var legitimate = PeerIdentity.Create( fullName );
        await using var victim = await CreateVictimAsync( "$SupersededVictim", remote, peer.Address, token );
        await PinAsync( peer, legitimate, remote, token );

        var stolenTail = new List<KeyEvent>( legitimate.Tail );
        var stolenKey = legitimate.CurrentKey;
        legitimate.Rotate();
        await using( var c2 = await peer.AcceptAsync( token ) )
        {
            var initial2 = await c2.ReadInitialMessageAsync( token );
            await c2.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial2, _systemClock.UtcNow, legitimate ), token );
            (await c2.ReadFrameAsync( token )).Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage );
        }

        await using var c3 = await peer.AcceptAsync( token );
        var initial3 = await c3.ReadInitialMessageAsync( token );
        using var stolenCredential = PeerCredential.Issue( stolenKey, fullName );
        var replay = PeerMessages.Build( ( ref FastByteWriter w ) => WriteAcceptedBody( ref w, initial3 ),
                                         stolenTail, stolenCredential.Encoded, stolenCredential.Key, null );
        await c3.SendZeroFrameAsync( replay, token );
        var answer = await ReadFrameOrNullAsync( c3, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage, "A superseded key is refused." );
        }
        PeerStore.ReadTrustedIdentity( $"Test/{remote}" )!.Seq.ShouldBe( 1, "And the pin does not roll back." );
    }

    /// <summary>
    /// The body of an AcceptedProtocols reply (without its identity block), as the harness's
    /// AcceptedProtocols builder writes it.
    /// </summary>
    void WriteAcceptedBody( ref FastByteWriter w, PeerInitialMessage initial )
    {
        using var ephemeral = new PeerEphemeral();
        var mac = RunPhaseProtection.Select( initial.MacCapabilities );
        w.WriteByte( PeerMessages.DNegoAcceptedProtocolsMessage );
        w.WriteUInt64( initial.Nonce );
        w.WriteTimeSpan( TimeSpan.Zero );
        w.WriteDateTime( _systemClock.UtcNow );
        w.WriteSmallUInt32( (uint)initial.AvailableProtocols.Count );
        foreach( var p in initial.AvailableProtocols ) w.WriteString( p );
        w.WriteSmallUInt32( (uint)ephemeral.PublicKey.Length );
        w.WriteBytes( ephemeral.PublicKey );
        w.WriteByte( (byte)mac );
        w.WriteByte( RunPhaseProtection.LocalCapabilities );
        w.WriteSmallUInt32( 0 ); // No certificate binding.
    }

    /// <summary>
    /// Builds an event the way an attacker would: any key revealed, any key signing.
    /// <see cref="KeyEvent.Create"/> refuses that, so the payload is signed here by hand.
    /// </summary>
    static KeyEvent ForgeEvent( string fullName, int seq, ECDsa revealed, ECDsa signer, byte[] nextCommit, KeyEvent previous )
    {
        var spki = revealed.ExportSubjectPublicKeyInfo();
        var prev = previous.GetDigest( fullName ).ToArray();
        var t = DateTime.UtcNow;
        t = new DateTime( t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc );
        var name = System.Text.Encoding.UTF8.GetBytes( fullName );
        using var payload = new MemoryStream();
        using( var w = new BinaryWriter( payload, System.Text.Encoding.UTF8, leaveOpen: true ) )
        {
            w.Write( "CK.AppIdentity.KEL/0"u8.ToArray() );
            w.Write( (ushort)name.Length );
            w.Write( name );
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( prev );
        }
        var sig = signer.SignHash( SHA512.HashData( payload.ToArray() ), DSASignatureFormat.IeeeP1363FixedFieldConcatenation );
        using var encoded = new MemoryStream();
        using( var w = new BinaryWriter( encoded ) )
        {
            w.Write( (uint)seq );
            w.Write( t.Ticks );
            w.Write( (ushort)spki.Length );
            w.Write( spki );
            w.Write( nextCommit );
            w.Write( prev );
            w.Write( (byte)sig.Length );
            w.Write( sig );
        }
        return KeyEvent.Read( encoded.ToArray() );
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
