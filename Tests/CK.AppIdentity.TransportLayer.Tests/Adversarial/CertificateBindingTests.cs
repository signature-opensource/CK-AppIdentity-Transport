using CK.AppIdentity.TransportLayer.Tests.Adversarial;
using CK.Core;
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
/// The certificate binding field: each side states, inside the signed transcript, the certificate it
/// is presenting, and each checks that statement against what actually arrived.
/// <para>
/// On a cleartext transport both sides state nothing, and these tests are about what happens when one
/// side states something anyway. That case is not a curiosity: it is what a peer configured for a
/// secured transport looks like to a peer that is not, and — once <c>mtls:</c> exists — what anything
/// terminating the channel in the middle looks like, since it has to present a certificate of its own
/// and cannot make the peer sign a statement about it.
/// </para>
/// <para>
/// What these tests cannot reach yet is the case where a certificate really was presented: that needs
/// a transport that reports one, so the mismatch and the omission on a secured connection belong with
/// the mutual TLS transport and its hostile cases. What is provable here is that the field is read at
/// the right offset, that its length is bounded, and that a statement which disagrees with the
/// connection is refused in both directions.
/// </para>
/// </summary>
[TestFixture]
public class CertificateBindingTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static byte[] SomeBinding() => RandomNumberGenerator.GetBytes( Transport.CertificateBindingLength );

    static ulong NewNonce() => BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) );

    Task<ApplicationIdentityService> CreateListenerAsync( string localName, string knownRemote, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = knownRemote;
        }, ConfigureFastClock, token: token );

    byte[] BuildInitial( string claimedFullName, PeerIdentity key, byte[]? certificateBinding )
    {
        using var ephemeral = new PeerEphemeral();
        return PeerMessages.InitialMessage( claimedFullName,
                                            instanceId: "BindInstance",
                                            availableProtocols: Array.Empty<string>(),
                                            expectedCommonProtocolCount: 0,
                                            nonceCreationTime: _systemClock.UtcNow,
                                            nonce: NewNonce(),
                                            ephemeralPublicKey: ephemeral.PublicKey,
                                            macCapabilities: RunPhaseProtection.LocalCapabilities,
                                            signWith: new[] { key },
                                            certificateBinding: certificateBinding );
    }

    /// <summary>Reads a frame, or null when the listener simply closes on us.</summary>
    static async Task<PeerWire.Frame2?> ReadOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try
        {
            return await c.ReadFrameAsync( token );
        }
        catch( System.IO.EndOfStreamException ) { return null; }
        catch( System.IO.IOException ) { return null; }
        catch( System.Net.Sockets.SocketException ) { return null; }
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_listener_answers_an_initiator_that_states_no_certificate_Async( CancellationToken token )
    {
        // The baseline this fixture needs. Without it, "the listener did not answer" below could just
        // as well mean the harness wrote a message no listener would ever accept.
        const string remote = "$BindOk";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$BindListenOk", remote, token );
        using var key = PeerIdentity.Create();

        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, certificateBinding: null ), token );

        var reply = await ReadOrNullAsync( c, token );
        reply.ShouldNotBeNull( "Stating no certificate is the truth on a cleartext connection, and must be accepted." );
        reply!.Value.IsZeroProtocol.ShouldBeTrue();
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_listener_refuses_an_initiator_that_states_a_certificate_it_did_not_present_Async( CancellationToken token )
    {
        // Same message as the baseline, one field changed. The initiator signs a statement that it is
        // presenting a certificate; the listener received none, so the two do not describe the same
        // connection and there is nothing to do but drop it.
        const string remote = "$BindClaim";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$BindListenClaim", remote, token );
        using var key = PeerIdentity.Create();

        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, SomeBinding() ), token );

        (await ReadOrNullAsync( c, token )).ShouldBeNull(
            "The statement is signed and verifiable, and still describes a connection that is not this one." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_listener_refuses_a_binding_of_the_wrong_length_Async( CancellationToken token )
    {
        // The field is a SHA-256 or it is absent. Accepting any length would make it an
        // attacker-sized allocation on a connection that has authenticated nothing yet.
        const string remote = "$BindLen";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var listener = await CreateListenerAsync( "$BindListenLen", remote, token );
        using var key = PeerIdentity.Create();

        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( BuildInitial( $"Test/{remote}/#Dev", key, new byte[5] ), token );

        (await ReadOrNullAsync( c, token )).ShouldBeNull( "Five bytes is not a SHA-256." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_initiator_refuses_a_listener_that_states_a_certificate_it_did_not_present_Async( CancellationToken token )
    {
        // The other direction, which is the one that matters for a client: the answer is signed by a
        // key the initiator has just adopted, everything else about it is correct, and it still has
        // to be refused because it describes a secured channel that this connection is not.
        const string remote = "$BindReply";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$BindInitiator";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var connection = await peer.AcceptAsync( token );
        var initial = await connection.ReadInitialMessageAsync( token );

        initial.CertificateBinding.ShouldBeNull(
            "A real initiator on a cleartext transport states no certificate: the field is one byte here." );

        var reply = PeerMessages.AcceptedProtocols( initial,
                                                    _systemClock.UtcNow,
                                                    new[] { peerKey },
                                                    certificateBinding: SomeBinding() );
        await connection.SendZeroFrameAsync( reply, token );

        var answer = await ReadOrNullAsync( connection, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                "An AcceptedProtocols whose certificate statement does not match the connection must " +
                "never be answered with FinalSuccess." );
        }
        feature.ConnectionAvailability.ShouldNotBe( ConnectionAvailability.Connected );
    }
}
