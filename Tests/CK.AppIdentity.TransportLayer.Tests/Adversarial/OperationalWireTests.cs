using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The operational credential and the end of an identity, on the wire (DESIGN-key-pre-rotation §5, §3).
/// </summary>
[TestFixture]
public class OperationalWireTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    Task<ApplicationIdentityService> CreateInitiatorAsync( string localName, string remote, string address, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{localName}";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );

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

    static async Task<PeerWire.Frame2?> ReadOrNullAsync( PeerConnection c, CancellationToken token )
    {
        try { return await c.ReadFrameAsync( token ); }
        catch( EndOfStreamException ) { return null; }
        catch( IOException ) { return null; }
    }

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token )
    {
        while( !condition() )
        {
            token.IsCancellationRequested.ShouldBeFalse( $"Timed out waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_transcript_must_be_signed_by_the_credential_key_not_the_identity_key_Async( CancellationToken token )
    {
        // The identity key no longer signs handshakes. A transcript it signs, even under a valid
        // credential and a pinned chain, is refused: otherwise the credential would bound nothing.
        const string remote = "$OpIdSigned";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        await using var peer = new AdversarialPeer();
        using var legitimate = PeerIdentity.Create( $"Test/{remote}/#Dev" );
        await using var initiator = await CreateInitiatorAsync( "$OpIdSignedInit", remote, peer.Address, token );

        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial, _systemClock.UtcNow, legitimate ), token );
            (await c1.ReadFrameAsync( token )).Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage, "Baseline must succeed first." );
        }

        await using var c2 = await peer.AcceptAsync( token );
        var initial2 = await c2.ReadInitialMessageAsync( token );
        var reply = PeerMessages.Build( ( ref FastByteWriter w ) => WriteAcceptedBody( ref w, initial2 ),
                                        legitimate.Tail, legitimate.Credential.Encoded, legitimate.CurrentKey, null );
        await c2.SendZeroFrameAsync( reply, token );
        var answer = await ReadOrNullAsync( c2, token );
        if( answer != null ) answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_credential_for_another_purpose_authenticates_nobody_Async( CancellationToken token )
    {
        const string remote = "$OpWrongEku";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        await using var peer = new AdversarialPeer();
        using var legitimate = PeerIdentity.Create( $"Test/{remote}/#Dev" );
        await using var initiator = await CreateInitiatorAsync( "$OpWrongEkuInit", remote, peer.Address, token );

        // A server-authentication credential, by the right issuer: what the mTLS transport presents.
        using var tlsLike = PeerCredential.Issue( legitimate.CurrentKey, legitimate.FullName, ekuOid: "1.3.6.1.5.5.7.3.1" );
        await using var c = await peer.AcceptAsync( token );
        var initial = await c.ReadInitialMessageAsync( token );
        var reply = PeerMessages.Build( ( ref FastByteWriter w ) => WriteAcceptedBody( ref w, initial ),
                                        legitimate.Tail, tlsLike.Encoded, tlsLike.Key, null );
        await c.SendZeroFrameAsync( reply, token );
        var answer = await ReadOrNullAsync( c, token );
        if( answer != null ) answer.Value.Discriminator.ShouldNotBe( PeerMessages.DNegoFinalSuccessMessage );
        PeerStore.ReadTrustedIdentity( $"Test/{remote}" ).ShouldBeNull( "Nothing is adopted, not even under AutoTrustKey.Once." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Credentials_renew_at_half_life_and_sessions_close_at_their_expiry_Async( CancellationToken token )
    {
        // Q9: a session does not outlive the credential that authenticated it. Time is moved forward on
        // the clock both parties share: past half the credential's life it is renewed, past its end the
        // connection made with the old one is closed, and the reconnection presents the new one.
        const string listenerName = "$OpLifeL";
        const string senderName = "$OpLifeS";
        PeerStore.ClearRemoteTrust( $"Test/{listenerName}" );
        PeerStore.ClearRemoteTrust( $"Test/{senderName}" );
        var clock = new SystemClockTester( 50 );
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{listenerName}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = senderName;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( clock ), token: token );
        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{senderName}";
            c["Parties:0:PartyName"] = listenerName;
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{AdversarialPeer.DefaultListenerPort}";
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( clock ), token: token );

        var senderSide = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderSide.ReadyTask.WaitAsync( token );
        var firstSession = senderSide.SessionId;
        var senderKeys = sender.GetRequiredFeature<ILocalKeys>();
        var firstCredential = senderKeys.State.Operational;

        // Half its life: renewed, and the session is untouched.
        clock.Offset = TimeSpan.FromDays( ILocalKeys.DefaultOperationalKeyDays / 2.0 + 0.5 );
        await WaitForAsync( () => senderKeys.State.Operational != firstCredential, "the credential renewal", token );
        await Task.Delay( 300, token );
        senderSide.SessionId.ShouldBe( firstSession, "A renewal does not touch existing sessions." );

        // Past the end of the credential the session was made with: closed, and made again.
        clock.Offset = TimeSpan.FromDays( ILocalKeys.DefaultOperationalKeyDays + 1 );
        await WaitForAsync( () => senderSide.SessionId != null && senderSide.SessionId != firstSession
                                  && senderSide.ConnectionAvailability == ConnectionAvailability.Connected,
                            "a new session", token );
        senderKeys.Alerts.ShouldBeEmpty();
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_decommissioned_identity_is_recorded_as_ended_and_cannot_be_reused_Async( CancellationToken token )
    {
        // The farewell: the abandonment travels in the tail, and the listener pins it from the event
        // alone - the session is refused anyway. Afterwards nothing under that identity is accepted,
        // and a new identity under the same name needs an operator, even under AutoTrustKey.Once.
        const string listenerName = "$OpEndL";
        const string remote = "$OpEnd";
        PeerStore.ClearRemoteTrust( $"Test/{listenerName}" );
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );
        var fullName = $"Test/{remote}/#Dev";
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{listenerName}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );
        var remoteKeys = listener.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>();
        var issues = listener.GetRequiredFeature<TransportManagerFeature>();

        using var party = PeerIdentity.Create( fullName );
        await KnockAsync( party, fullName, token );
        await WaitForAsync( () => remoteKeys.TrustedEvent?.Seq == 0, "the first contact to be pinned", token );

        party.Abandon();
        await KnockAsync( party, fullName, token );
        await WaitForAsync( () => remoteKeys.IsTerminated, "the abandonment to be pinned", token );
        PeerStore.ReadTrustedIdentity( $"Test/{remote}" )!.IsAbandonment.ShouldBeTrue( "Persisted: it survives a restart." );

        // A new identity under the same name: refused, and no approval is offered for it.
        using var reborn = PeerIdentity.Create( fullName );
        await KnockAsync( reborn, fullName, token );
        await Task.Delay( 300, token );
        remoteKeys.IsTerminated.ShouldBeTrue( "AutoTrustKey.Once does not adopt over an ended identity." );
        issues.GetPeeringIssues().ShouldNotContain( i => i.FullName == fullName && i.CanAcceptRemoteIdentity );

        // An operator clears the pin: the new identity can now be adopted.
        remoteKeys.SetTrustedIdentity( TestHelper.Monitor, null ).ShouldBeTrue();
        await KnockAsync( reborn, fullName, token );
        await WaitForAsync( () => remoteKeys.TrustedEvent is { IsAbandonment: false }, "the new identity to be adopted", token );
        remoteKeys.TrustedEvent!.GetDigest( fullName ).ToArray().ShouldBe( reborn.HeadDigest );
    }

    async Task KnockAsync( PeerIdentity party, string fullName, CancellationToken token )
    {
        using var ephemeral = new PeerEphemeral();
        var initial = PeerMessages.InitialMessage( fullName,
                                                   instanceId: "EndInstance",
                                                   availableProtocols: Array.Empty<string>(),
                                                   expectedCommonProtocolCount: 0,
                                                   nonceCreationTime: _systemClock.UtcNow,
                                                   nonce: BitConverter.ToUInt64( System.Security.Cryptography.RandomNumberGenerator.GetBytes( 8 ) ),
                                                   ephemeralPublicKey: ephemeral.PublicKey,
                                                   macCapabilities: RunPhaseProtection.LocalCapabilities,
                                                   signWith: party );
        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( initial, token );
        await ReadOrNullAsync( c, token );
    }
}
