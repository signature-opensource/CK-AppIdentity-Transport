using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The alerts of DESIGN-key-pre-rotation §8, end to end: what a party learns, from the wire, when its
/// next key leaked.
/// <para>
/// Pre-rotation makes a takeover impossible unless the next key leaks. When it does, noticing is the
/// only defence left, and the victim's own handshake is refused: the refusal itself must carry what
/// the remote pins, signed.
/// </para>
/// </summary>
[TestFixture]
public class IdentityAlertWireTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    const string Listener = "$AlertL";
    const string Victim = "$AlertV";
    static string ListenerFullName => $"Test/{Listener}/#Dev";
    static string VictimFullName => $"Test/{Victim}/#Dev";

    Task<ApplicationIdentityService> CreateListenerAsync( CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{Listener}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = Victim;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, s => s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock ), token: token );

    Task<ApplicationIdentityService> CreateVictimAsync( IDataProtectionProvider protector, string address, string autoTrust, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/{Victim}";
            c["Parties:0:PartyName"] = Listener;
            c["Parties:0:Address"] = address;
            c["Parties:0:AutoTrustKey"] = autoTrust;
        }, s =>
        {
            s.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );
            // Our own protector, so that the test can open the victim's key store like a thief.
            s.AddSingleton( protector );
        }, token: token );

    static string DefaultAddress => $"tcp:127.0.0.1:{AdversarialPeer.DefaultListenerPort}";

    static void ClearAll()
    {
        PeerStore.ClearRemoteTrust( $"Test/{Listener}" );
        PeerStore.ClearRemoteTrust( $"Test/{Victim}" );
    }

    static async Task WaitForAsync( Func<bool> condition, string what, CancellationToken token )
    {
        while( !condition() )
        {
            token.IsCancellationRequested.ShouldBeFalse( $"Timed out waiting for {what}." );
            await Task.Delay( 20, token );
        }
    }

    /// <summary>
    /// Connects as the thief: an InitialMessage claiming the victim, presenting <paramref name="thief"/>'s
    /// log and signed with its current key. The listener applies the tail while it reads the message.
    /// </summary>
    async Task KnockAsAsync( PeerIdentity thief, CancellationToken token )
    {
        using var ephemeral = new PeerEphemeral();
        var initial = PeerMessages.InitialMessage( VictimFullName,
                                                   instanceId: "ThiefInstance",
                                                   availableProtocols: Array.Empty<string>(),
                                                   expectedCommonProtocolCount: 0,
                                                   nonceCreationTime: _systemClock.UtcNow,
                                                   nonce: BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) ),
                                                   ephemeralPublicKey: ephemeral.PublicKey,
                                                   macCapabilities: RunPhaseProtection.LocalCapabilities,
                                                   signWith: thief );
        await using var c = await AdversarialPeer.ConnectAsync( cancellation: token );
        await c.SendZeroFrameAsync( initial, token );
        try { await c.ReadFrameAsync( token ); }
        catch( EndOfStreamException ) { }
        catch( IOException ) { }
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_victim_learns_its_identity_was_taken_over_from_the_refusal_Async( CancellationToken token )
    {
        ClearAll();
        var protector = new HeaderProtector();
        await using var listener = await CreateListenerAsync( token );

        // 1. The victim connects: both sides pin each other's inception.
        KeyEvent e0;
        ECDsa stolenNext;
        await using( var victim = await CreateVictimAsync( protector, DefaultAddress, "Once", token ) )
        {
            await victim.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
            e0 = victim.GetRequiredFeature<ILocalKeys>().State.Head;
            // 2. Its NEXT key leaks: the only thing that can move its pin anywhere.
            stolenNext = IdentityStoreHelper.OpenKey( victim, protector, 1 );
        }
        using var _stolen = stolenNext;

        // 3. The thief rotates the victim's identity onto a key of its own, at the listener. This is a
        //    valid rotation: the listener cannot tell, and must accept it.
        using var thiefNext = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var e1 = KeyEvent.Create( VictimFullName, 1, DateTime.UtcNow, stolenNext, KeyEvent.ComputeCommit( thiefNext.ExportSubjectPublicKeyInfo() ), e0 );
        using( var thief = PeerIdentity.Adopt( VictimFullName, new[] { e0, e1 }, stolenNext, thiefNext ) )
        {
            await KnockAsAsync( thief, token );
        }
        await WaitForAsync( () => PeerStore.ReadTrustedIdentity( $"Test/{Victim}" )?.Seq == 1, "the listener to follow the thief's rotation", token );

        // 4. The victim comes back. Its handshake is refused (a rollback, from the listener's view), and
        //    the signed refusal says what the listener pins: beyond the victim's own log.
        await using var back = await CreateVictimAsync( protector, DefaultAddress, "Once", token );
        var keys = back.GetRequiredFeature<ILocalKeys>();
        await WaitForAsync( () => keys.Alerts.Any( a => a.Kind == IdentityAlertKind.IdentityTakenOver ), "the takeover alert", token );
        var alert = keys.Alerts.Single( a => a.Kind == IdentityAlertKind.IdentityTakenOver );
        alert.IsAboutSelf.ShouldBeTrue();
        alert.Seq.ShouldBe( 1 );
        alert.ReportedBy.ShouldContain( ListenerFullName );
        alert.ObservedDigest.ToArray().ShouldBe( e1.GetDigest( VictimFullName ).ToArray() );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_taken_over_identity_is_taken_back_with_the_recovery_key_Async( CancellationToken token )
    {
        // The whole story: the next key leaks, a thief moves the listener's pin, the victim learns it
        // from the refusal, recovers, and the listener follows the recovery - the thief's chain is
        // superseded because it could not change the recovery commitment.
        ClearAll();
        var protector = new HeaderProtector();
        await using var listener = await CreateListenerAsync( token );

        KeyEvent e0;
        ECDsa stolenNext;
        await using( var victim = await CreateVictimAsync( protector, DefaultAddress, "Once", token ) )
        {
            await victim.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
            e0 = victim.GetRequiredFeature<ILocalKeys>().State.Head;
            stolenNext = IdentityStoreHelper.OpenKey( victim, protector, 1 );
        }
        using var _stolen = stolenNext;
        using var thiefNext = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var e1 = KeyEvent.Create( VictimFullName, 1, DateTime.UtcNow, stolenNext, KeyEvent.ComputeCommit( thiefNext.ExportSubjectPublicKeyInfo() ), e0 );
        using( var thief = PeerIdentity.Adopt( VictimFullName, new[] { e0, e1 }, stolenNext, thiefNext ) )
        {
            await KnockAsAsync( thief, token );
        }
        await WaitForAsync( () => PeerStore.ReadTrustedIdentity( $"Test/{Victim}" )?.Seq == 1, "the thief's rotation", token );

        await using var back = await CreateVictimAsync( protector, DefaultAddress, "Once", token );
        var keys = back.GetRequiredFeature<ILocalKeys>();
        await WaitForAsync( () => keys.Alerts.Any( a => a.Kind == IdentityAlertKind.IdentityTakenOver ), "the takeover alert", token );

        // The operator recovers. The recovery key is in the key store here: the thief only took the next key.
        keys.Recover( TestHelper.Monitor ).ShouldBeTrue();
        var recoveredHead = keys.State.Head;

        var side = back.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await WaitForAsync( () => side.ConnectionAvailability == ConnectionAvailability.Connected, "the reconnection", token );
        var pinned = PeerStore.ReadTrustedIdentity( $"Test/{Victim}" )!;
        pinned.GetDigest( VictimFullName ).ToArray().ShouldBe( recoveredHead.GetDigest( VictimFullName ).ToArray(),
            "The listener dropped the thief's chain and pins the recovered identity." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_fork_raises_duplicity_on_the_remote_and_a_fork_alert_on_the_victim_Async( CancellationToken token )
    {
        ClearAll();
        var protector = new HeaderProtector();
        await using var listener = await CreateListenerAsync( token );

        // 1. The victim connects, then rotates: its current key is now key 1.
        KeyEvent e0;
        ECDsa stolenCurrent;
        await using( var victim = await CreateVictimAsync( protector, DefaultAddress, "Once", token ) )
        {
            await victim.AllRemotes.Single().GetRequiredFeature<TransportFeature>().ReadyTask.WaitAsync( token );
            var keys = victim.GetRequiredFeature<ILocalKeys>();
            e0 = keys.State.Head;
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
            // 2. Key 1 leaks. It is the key event 0 committed to: whoever holds it can write AN event 1.
            stolenCurrent = IdentityStoreHelper.OpenKey( victim, protector, 1 );
        }
        using var _stolen = stolenCurrent;

        // 3. The thief writes its own event 1 and reaches the listener first.
        using var thiefNext = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var forked = KeyEvent.Create( VictimFullName, 1, DateTime.UtcNow, stolenCurrent, KeyEvent.ComputeCommit( thiefNext.ExportSubjectPublicKeyInfo() ), e0 );
        using( var thief = PeerIdentity.Adopt( VictimFullName, new[] { e0, forked }, stolenCurrent, thiefNext ) )
        {
            await KnockAsAsync( thief, token );
        }
        await WaitForAsync( () => PeerStore.ReadTrustedIdentity( $"Test/{Victim}" )?.Seq == 1, "the listener to pin the forked event", token );

        // 4. The victim comes back with ITS event 1: two valid events at the same sequence.
        await using var back = await CreateVictimAsync( protector, DefaultAddress, "Once", token );
        var victimKeys = back.GetRequiredFeature<ILocalKeys>();
        await WaitForAsync( () => victimKeys.Alerts.Any( a => a.Kind == IdentityAlertKind.IdentityForked ), "the fork alert on the victim", token );
        victimKeys.Alerts.Single( a => a.Kind == IdentityAlertKind.IdentityForked ).ReportedBy.ShouldContain( ListenerFullName );

        // The listener saw the proof itself.
        var listenerAlert = listener.GetRequiredFeature<ILocalKeys>().Alerts.Single( a => a.Kind == IdentityAlertKind.RemoteDuplicity );
        listenerAlert.Subject.ShouldBe( VictimFullName );
        listenerAlert.Seq.ShouldBe( 1 );
        var evidence = Path.Combine( ApplicationIdentityServiceConfiguration.DefaultStoreRootPath, "#Dev", "Test", Victim, "Duplicity" );
        Directory.EnumerateFiles( evidence, "*.event" ).Count().ShouldBe( 2, "Both events are kept as evidence." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_statement_counts_only_from_an_authenticated_remote_Async( CancellationToken token )
    {
        // Anyone can sign a refusal with a key of its own and state anything in it. If that raised an
        // alert, any stranger answering a connection could page an operator.
        ClearAll();
        await using var peer = new AdversarialPeer();
        using var stranger = PeerIdentity.Create( ListenerFullName );
        await using var victim = await CreateVictimAsync( new HeaderProtector(), peer.Address, "Never", token );
        var keys = victim.GetRequiredFeature<ILocalKeys>();
        var claim = new PeerStatement( 5, RandomNumberGenerator.GetBytes( 32 ) );

        // Not pinned: the refusal is merely self-asserted.
        await using( var c1 = await peer.AcceptAsync( token ) )
        {
            var initial = await c1.ReadInitialMessageAsync( token );
            await c1.SendZeroFrameAsync( PeerMessages.RejectRemote( initial.Nonce, 8 /*IdentityConflict*/, null, null, stranger, claim ), token );
            await Task.Delay( 300, token );
        }
        keys.Alerts.ShouldBeEmpty( "A statement from a sender we have not authenticated says nothing." );

        // The very same refusal, once the sender is pinned: now it counts. This is what makes the
        // assertion above evidence rather than a test that could never have seen an alert.
        victim.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>().SetTrustedIdentity( TestHelper.Monitor, stranger.Head ).ShouldBeTrue();
        await using( var c2 = await peer.AcceptAsync( token ) )
        {
            var initial = await c2.ReadInitialMessageAsync( token );
            await c2.SendZeroFrameAsync( PeerMessages.RejectRemote( initial.Nonce, 8, null, null, stranger, claim ), token );
            await WaitForAsync( () => keys.Alerts.Any(), "the alert from the authenticated remote", token );
        }
        keys.Alerts.Single().Kind.ShouldBe( IdentityAlertKind.IdentityTakenOver );
    }
}
