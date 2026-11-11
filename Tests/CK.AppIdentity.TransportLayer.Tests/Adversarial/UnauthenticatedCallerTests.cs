using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
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
/// What a caller that is not authenticated as a known remote can do to it on a real listener: nothing. It doesn't fill
/// its nonce cache (TM-2), doesn't overwrite its issues (TM-4), and a FinalSuccess of another connection doesn't complete
/// a handshake (TM-3).
/// </summary>
[TestFixture]
public class UnauthenticatedCallerTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static ulong NewNonce() => BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) );

    byte[] BuildInitial( string claimedFullName, PeerIdentity key, ulong nonce, TransportFeature? listened = null, bool canAutoTrust = false )
    {
        using var ephemeral = new PeerEphemeral();
        var protocols = listened?.BestRegisteredProtocols.Select( p => p.FullName ).ToArray() ?? Array.Empty<string>();
        return PeerMessages.InitialMessage( claimedFullName,
                                            instanceId: "AdvInstance",
                                            availableProtocols: protocols,
                                            expectedCommonProtocolCount: protocols.Length,
                                            nonceCreationTime: _systemClock.UtcNow,
                                            nonce: nonce,
                                            ephemeralPublicKey: ephemeral.PublicKey,
                                            macCapabilities: RunPhaseProtection.LocalCapabilities,
                                            signWith: key,
                                            canAutoTrust: canAutoTrust );
    }

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

    [Test, CancelAfter( 60000 )]
    public async Task a_self_asserted_caller_does_not_fill_the_nonce_cache_of_a_pinned_remote_Async( CancellationToken token )
    {
        const string remote = "$TM2Pinned";
        PeerStore.ClearLocalParty( "Test/$TM2Listen" );
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TM2Listen";
            c["Defaults:AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = remote;
        }, ConfigureFastClock, token: token );
        var fullName = $"Test/{remote}/#Dev";
        var keys = listener.Remotes.Single().GetRequiredFeature<IRemoteKeys>();
        using var genuine = PeerIdentity.Create( fullName );
        keys.SetTrustedIdentity( TestHelper.Monitor, genuine.Head ).ShouldBeTrue();

        // A log of its own, far ahead of the pin: its events are not verified (TooFarBehind), its signature is only
        // self-asserted, and it is too far for the listener to ask its events.
        using var stranger = PeerIdentity.Create( fullName );
        for( int i = 0; i < KeyEventChain.MaxEventWindow + 8; ++i ) stranger.Rotate();
        var nonce = NewNonce();
        var time = _systemClock.UtcNow;
        await using( var c = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c.SendZeroFrameAsync( BuildInitial( fullName, stranger, nonce ), token );
            (await ReadOrNullAsync( c, token )).ShouldNotBeNull( "The listener decided." );
        }
        keys.TrustedEvent.ShouldBe( genuine.Head );
        keys.CheckAndAddNonceValue( TestHelper.Monitor, new TimedNonce( time, nonce ), LogLevel.None )
            .ShouldBeTrue( "The nonce of a caller that is not authenticated as the pinned remote is not recorded." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task an_unauthenticated_caller_does_not_overwrite_the_issue_of_a_remote_that_does_not_listen_here_Async( CancellationToken token )
    {
        const string listened = "$TM4Listened";
        const string initiated = "$TM4Initiated";
        PeerStore.ClearRemoteTrust( $"Test/{listened}" );
        PeerStore.ClearRemoteTrust( $"Test/{initiated}" );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TM4Listen";
            c["Defaults:AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = listened;
            // A remote this party initiates to: it doesn't listen for it.
            c["Parties:1:PartyName"] = initiated;
            c["Parties:1:Address"] = "tcp:127.0.0.1:1";
        }, ConfigureFastClock, token: token );
        var feature = listener.GetRequiredFeature<TransportManagerFeature>();
        var fullName = $"Test/{initiated}/#Dev";

        using var stranger = PeerIdentity.Create( fullName );
        await using( var c = await AdversarialPeer.ConnectAsync( cancellation: token ) )
        {
            await c.SendZeroFrameAsync( BuildInitial( fullName, stranger, NewNonce() ), token );
            var reply = await ReadOrNullAsync( c, token );
            reply.ShouldNotBeNull();
            reply.Value.Discriminator.ShouldBe( PeerMessages.DNegoFinalFailureMessage,
                "Nothing authenticates the caller as this remote: no signed reply, no issue." );
        }
        await Task.Delay( 500, token );
        feature.GetPeeringIssues().ShouldNotContain( i => i.Kind == PeeringIssueKind.InitiatorConflict );
    }

    [Test, CancelAfter( 60000 )]
    public async Task new_keys_under_the_name_of_a_remote_do_not_push_its_approval_item_out_Async( CancellationToken token )
    {
        const string remote = "$TM7Waiting";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TM7Listen";
            c["Defaults:AlwaysListening"] = "True";
            c["Defaults:AutoTrustKey"] = "Never";
            c["Parties:0:PartyName"] = remote;
        }, ConfigureFastClock, token: token );
        var fullName = $"Test/{remote}/#Dev";
        var transport = listener.Remotes.Single().GetRequiredFeature<TransportFeature>();
        var commitment = RandomNumberGenerator.GetBytes( 32 );

        // One attempt of a caller: the listener's nonce of the approval code for its key. Retried when the listener
        // closes before answering (its 2 seconds negotiation budget on a loaded machine): the same key and commitment
        // find the same item.
        async Task<byte[]?> AttemptAsync( PeerIdentity key, byte[] approvalCommitment )
        {
            var protocols = transport.BestRegisteredProtocols.Select( p => p.FullName ).ToArray();
            for( int retry = 0; ; ++retry )
            {
                using var ephemeral = new PeerEphemeral();
                var initial = PeerMessages.InitialMessage( fullName, "AdvInstance", protocols, protocols.Length, _systemClock.UtcNow, NewNonce(),
                                                           ephemeral.PublicKey, RunPhaseProtection.LocalCapabilities, key,
                                                           canAutoTrust: true, approvalCommitment: approvalCommitment );
                await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
                await c.SendZeroFrameAsync( initial, token );
                var reply = await ReadOrNullAsync( c, token );
                if( reply == null && retry < 3 ) continue;
                reply.ShouldNotBeNull();
                reply.Value.Discriminator.ShouldBe( PeerMessages.DNegoRejectRemote, "An approval is required." );
                return PeerMessages.ReadApprovalNonce( reply.Value.Payload );
            }
        }

        using var genuine = PeerIdentity.Create( fullName );
        var first = await AttemptAsync( genuine, commitment );
        first.ShouldNotBeNull();
        // Strangers present new keys under the remote's name, more than the listener keeps.
        for( int i = 0; i < 2 * ApprovalSessionMaxPendingKeys; ++i )
        {
            using var stranger = PeerIdentity.Create( fullName );
            await AttemptAsync( stranger, RandomNumberGenerator.GetBytes( 32 ) );
        }
        var second = await AttemptAsync( genuine, commitment );
        second.ShouldBe( first, "The item of the remote's key is still there: its code doesn't change." );
    }

    // ApprovalSession.MaxPendingKeys (internal).
    const int ApprovalSessionMaxPendingKeys = 4;

    [Test, CancelAfter( 60000 )]
    public async Task a_FinalSuccess_must_confirm_the_listener_ephemeral_key_of_its_connection_Async( CancellationToken token )
    {
        const string remote = "$TM3Initiator";
        PeerStore.ClearLocalParty( "Test/$TM3Listen" );
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$TM3Listen";
            c["Defaults:AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = remote;
        }, ConfigureFastClock, token: token );
        var fullName = $"Test/{remote}/#Dev";
        var transport = listener.Remotes.Single().GetRequiredFeature<TransportFeature>();
        using var key = PeerIdentity.Create( fullName );
        transport.RemoteKeys.SetTrustedIdentity( TestHelper.Monitor, key.Head ).ShouldBeTrue();

        // Runs a handshake up to the FinalSuccess, built by the given function from the listener's ephemeral key.
        async Task<bool> HandshakeAsync( Func<ulong, byte[], byte[]> finalSuccess )
        {
            var nonce = NewNonce();
            await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
            await c.SendZeroFrameAsync( BuildInitial( fullName, key, nonce, transport, canAutoTrust: true ), token );
            var accepted = await c.ReadFrameAsync( token );
            accepted.Discriminator.ShouldBe( PeerMessages.DNegoAcceptedProtocolsMessage );
            await c.SendZeroFrameAsync( finalSuccess( nonce, PeerMessages.ReadListenerEphemeral( accepted.Payload ) ), token );
            var deadline = DateTime.UtcNow.AddSeconds( 3 );
            while( DateTime.UtcNow < deadline )
            {
                if( transport.ConnectionAvailability == ConnectionAvailability.Connected ) return true;
                await Task.Delay( 50, token );
            }
            return false;
        }

        // A FinalSuccess that confirms nothing (what a captured one of another connection is).
        (await HandshakeAsync( ( n, _ ) => PeerMessages.FinalSuccess( n, TimeSpan.Zero, null, key ) )).ShouldBeFalse();
        // One that confirms another connection's ephemeral key.
        using var other = new PeerEphemeral();
        (await HandshakeAsync( ( n, _ ) => PeerMessages.FinalSuccess( n, TimeSpan.Zero, other.PublicKey, key ) )).ShouldBeFalse();
        // The genuine one.
        (await HandshakeAsync( ( n, e ) => PeerMessages.FinalSuccess( n, TimeSpan.Zero, e, key ) )).ShouldBeTrue();
    }
}
