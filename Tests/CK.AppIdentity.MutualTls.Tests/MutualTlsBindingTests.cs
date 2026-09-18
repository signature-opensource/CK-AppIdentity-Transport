using CK.AppIdentity.TransportLayer;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.MutualTls.Tests;

/// <summary>
/// The rows of the binding table that need a certificate actually on the wire.
/// <para>
/// Until now the harness spoke cleartext, so only "a peer states a certificate on a connection that
/// has none" could be reached. With TLS it can present one certificate and state another, which is
/// exactly what something terminating the channel between two peers has to do: it completes a TLS
/// handshake with each side using a key of its own, and it cannot make either peer sign a statement
/// about a certificate it never held.
/// </para>
/// <para>
/// That case is the reason the binding exists, and it is the one that would pass silently if the
/// binding were removed — TLS alone is perfectly happy, both handshakes succeed, and the Zero
/// Protocol signature verifies, because a relay forwards the signed bytes unchanged.
/// </para>
/// </summary>
[TestFixture]
public class MutualTlsBindingTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureServices( ServiceCollection services )
    {
        services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
        services.AddSingleton<MutualTlsTransportTypeService>();
        services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<MutualTlsTransportTypeService>() );
    }

    /// <summary>
    /// A real initiator pointed at the harness, which terminates TLS itself.
    /// </summary>
    Task<ApplicationIdentityService> CreateInitiatorAsync( string localName, string remote, string address, CancellationToken token )
        => AppIdentityTestHelper.CreateServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureServices, token );

    /// <summary>Reads a frame, or null when the peer closes on us instead of replying.</summary>
    static async Task<PeerWire.Frame2?> ReadOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try
        {
            return await c.ReadFrameAsync( token );
        }
        catch( System.IO.EndOfStreamException ) { return null; }
        catch( System.IO.IOException ) { return null; }
        catch( SocketException ) { return null; }
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_harness_completes_an_mtls_handshake_when_it_tells_the_truth_Async( CancellationToken token )
    {
        // The gate for this whole fixture. A harness that cannot be accepted when it is honest makes
        // every rejection below meaningless — it would be the harness being wrong, not the binding
        // being right.
        const string remote = "$MtlsOk";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        using var cert = PeerCertificate.Create();
        await using var peer = new AdversarialPeer( cert );
        using var peerKey = PeerIdentity.Create();

        peer.Address.ShouldStartWith( "mtls:" );

        await using var sender = await CreateInitiatorAsync( "$MtlsOkInit", remote, peer.Address, token );
        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var c = await peer.AcceptAsync( token );
        c.ReceivedCertificate.ShouldNotBeNull( "The initiator presents a client certificate: this transport is mutual." );

        var initial = await c.ReadInitialMessageAsync( token );
        initial.CertificateBinding.ShouldNotBeNull( "On TLS the initiator states what it presented." );
        initial.CertificateBinding!.ShouldBe( PeerCertificate.BindingOf( c.ReceivedCertificate! ),
            "And what it states is the certificate the harness actually received - computed here, " +
            "independently, so that a bug cannot make both sides agree on the same wrong number." );

        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial,
                                                                    _systemClock.UtcNow,
                                                                    new[] { peerKey },
                                                                    certificateBinding: c.TruthfulBinding ), token );

        var final = await c.ReadFrameAsync( token );
        final.Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage,
            "An honest statement over a real TLS channel must be accepted." );
        await feature.ReadyTask.WaitAsync( token );
        feature.ConnectionAvailability.ShouldBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_peer_that_states_a_certificate_it_is_not_presenting_is_refused_Async( CancellationToken token )
    {
        // THE relay case. Everything is correct except one field: the handshake is real TLS, the
        // signature verifies, the key is one the initiator is willing to adopt. The peer simply
        // states a certificate other than the one it presented — which is all a machine in the
        // middle can do, because it holds its own key and not the one it is impersonating.
        const string remote = "$MtlsRelay";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        using var presented = PeerCertificate.Create();
        using var claimed = PeerCertificate.Create( "SomeoneElse" );
        await using var peer = new AdversarialPeer( presented );
        using var peerKey = PeerIdentity.Create();

        await using var sender = await CreateInitiatorAsync( "$MtlsRelayInit", remote, peer.Address, token );
        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );

        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial,
                                                                    _systemClock.UtcNow,
                                                                    new[] { peerKey },
                                                                    certificateBinding: claimed.Binding ), token );

        var answer = await ReadOrNullAsync( c, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                "The TLS channel and the signed identity must be the same channel. They are not here." );
        }
        feature.ConnectionAvailability.ShouldNotBe( ConnectionAvailability.Connected );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_peer_that_states_nothing_on_a_TLS_connection_is_refused_Async( CancellationToken token )
    {
        // The omission, which is the same failure seen from the other side: a peer that believes it
        // is on a cleartext transport while its counterpart is on TLS. Nothing is under attack and
        // nothing works either, which is why it must say so rather than half-connect.
        const string remote = "$MtlsSilent";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        using var cert = PeerCertificate.Create();
        await using var peer = new AdversarialPeer( cert );
        using var peerKey = PeerIdentity.Create();

        await using var sender = await CreateInitiatorAsync( "$MtlsSilentInit", remote, peer.Address, token );
        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        await using var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );

        await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial,
                                                                    _systemClock.UtcNow,
                                                                    new[] { peerKey },
                                                                    certificateBinding: null ), token );

        var answer = await ReadOrNullAsync( c, token );
        if( answer != null )
        {
            answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage,
                "A certificate arrived and the peer says it presented none: the two are not describing " +
                "the same connection." );
        }
        feature.ConnectionAvailability.ShouldNotBe( ConnectionAvailability.Connected );
    }
}
