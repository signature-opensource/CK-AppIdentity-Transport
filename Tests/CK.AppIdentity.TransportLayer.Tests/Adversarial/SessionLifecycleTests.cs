using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Requirement A of the C1-b design: the session key and frame counter lifecycle.
/// <para>
/// This is the gate on using AES-GMAC at all. GMAC's failure mode is a repeated (key, nonce) pair
/// with different data: it leaks the authentication subkey and allows arbitrary forgery — a total
/// break, not a degradation. Everything that makes that unreachable is a lifecycle property, so
/// each one is pinned here rather than argued for in a comment.
/// </para>
/// <para>
/// The concern is not hypothetical for this codebase: H4 was a pooled object carrying state into a
/// different remote, and M6 is a send path that can re-run on a retry. Those are precisely the two
/// shapes that would produce a reused nonce.
/// </para>
/// </summary>
[TestFixture]
public class SessionLifecycleTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static ReadOnlySequence<byte> Seq( byte[] b ) => new ReadOnlySequence<byte>( b );

    [Test, CancelAfter( 40000 )]
    public async Task Every_connection_derives_its_own_session_key_Async( CancellationToken token )
    {
        // The central invariant. If two connections ever shared a key, both would start their
        // counters at zero and immediately reuse (key, nonce) pairs with different data.
        const string remote = "$AdvLifecycle";
        PeerStore.ClearRemoteTrust( $"Test/{remote}" );

        await using var peer = new AdversarialPeer();
        using var peerKey = PeerIdentity.Create();

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$Lifecycle";
            c["Parties:0:PartyName"] = remote;
            c["Parties:0:Address"] = peer.Address;
            c["Parties:0:AutoTrustKey"] = "Once";
        }, ConfigureFastClock, token: token );

        var feature = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();

        // The harness derives the session itself, exactly as the real listener does. That keeps the
        // observation deterministic: reading feature.SessionId would race the reconnect churn that
        // dropping each connection deliberately causes.
        var sessions = new List<string>();
        var initiatorEphemerals = new List<string>();
        for( int i = 0; i < 3; ++i )
        {
            await using var c = await peer.AcceptAsync( token );
            var initial = await c.ReadInitialMessageAsync( token );

            // The initiator's ephemeral public key must be new every time. A cached one would mean
            // the same shared secret, hence the same session key.
            initiatorEphemerals.Add( Convert.ToHexString( initial.EphemeralPublicKey ) );

            using var ephemeral = new PeerEphemeral();
            var alg = RunPhaseProtection.Select( initial.MacCapabilities );
            var transcript = RunPhaseProtection.BuildTranscript( initial.MacCapabilities, alg, 0,
                                                                 initial.FullName, "Test/$Lifecycle/#Dev" );
            using var derived = RunPhaseProtection.Derive( ephemeral.Key, initial.EphemeralPublicKey,
                                                           alg, initial.Nonce, transcript, isInitiator: false );
            sessions.Add( derived.SessionId );

            await c.SendZeroFrameAsync( PeerMessages.AcceptedProtocols( initial.Nonce,
                                                                        TimeSpan.Zero,
                                                                        _systemClock.UtcNow,
                                                                        initial.AvailableProtocols,
                                                                        ephemeral.PublicKey,
                                                                        alg,
                                                                        new[] { peerKey } ), token );
            (await c.ReadFrameAsync( token )).Discriminator.ShouldBe( PeerMessages.DNegoFinalSuccessMessage,
                "The handshake must complete, or the session we derived is not the one in use." );
            // Dropping the connection forces a reconnect, which must start from new key material.
        }

        initiatorEphemerals.Distinct().Count().ShouldBe( 3,
            "The ephemeral ECDH key must be created per connection. It lives on the Transport for " +
            "exactly this reason: OutgoingInitialMessage is cached on the TransportFeature and " +
            "reused across attempts, so an ephemeral held there would repeat." );
        sessions.Distinct().Count().ShouldBe( 3,
            "Each connection must derive its own session key. A shared key across reconnects is the " +
            "GMAC nonce-reuse case, which is a total break." );
    }

    [Test, CancelAfter( 40000 )]
    public async Task Session_keys_are_released_when_the_connection_dies_Async( CancellationToken token )
    {
        // Requirement A: key material is owned by the connection and dies with it. Before this was
        // implemented the session keys and the ephemeral private key simply outlived the transport,
        // leaking a CNG handle per connection along the way.
        // Two REAL peers: a stable connection to observe teardown against. Against the harness the
        // connection churns by design, which would race the observation.
        await using var listener = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$RelListen";
            c["AutoTrustKey"] = "Once";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = "$RelSend";
        }, ConfigureFastClock, token: token );

        await using var sender = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = "Test/$RelSend";
            c["AutoTrustKey"] = "Once";
            c["Parties:0:PartyName"] = "$RelListen";
            c["Parties:0:Address"] = $"tcp:127.0.0.1:{AdversarialPeer.DefaultListenerPort}";
        }, ConfigureFastClock, token: token );

        var senderTransport = sender.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        var listenerTransport = listener.AllRemotes.Single().GetRequiredFeature<TransportFeature>();
        await senderTransport.ReadyTask.WaitAsync( token );
        await listenerTransport.ReadyTask.WaitAsync( token );

        // Hold THE transport instance. Re-reading feature.SessionId would not test anything: the
        // feature swaps its transport on teardown, so that value goes null whether or not the keys
        // were released — a test reading it passes against an implementation that releases nothing.
        var transport = senderTransport.CurrentTransport;
        transport.ShouldNotBeNull();
        var session = transport!.SessionId;
        session.ShouldNotBeNull( "Connected: the session exists." );
        listenerTransport.SessionId.ShouldBe( session, "Both peers hold the same session." );

        // Switch the remote off: this transport is destroyed and must take its key material with it.
        senderTransport.SwitchOff( "Releasing the session." );

        var deadline = DateTime.UtcNow.AddSeconds( 15 );
        while( transport.SessionId != null && DateTime.UtcNow < deadline )
        {
            await Task.Delay( 50, token );
        }
        transport.SessionId.ShouldBeNull(
            "Destroying a transport must release its session keys and its ephemeral private key. " +
            "Without it they outlive the connection until the GC gets round to them, and each " +
            "connection leaks a CNG handle." );
        transport.NegotiatedMacAlgorithm.ShouldBeNull( "The protection is gone, not merely emptied." );
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void The_counter_advances_even_for_two_identical_frames( MacAlgorithm alg )
    {
        // The M6 shape. That send path can re-run on a retry, so the question is what happens when
        // the same bytes are signed twice. Re-sending identical data under the same nonce would be
        // harmless; what must be impossible is the same nonce with DIFFERENT data. The counter
        // advancing unconditionally is what guarantees a nonce is never revisited at all.
        var (i, l) = MakePair( alg );
        using( i )
        using( l )
        {
            var header = new byte[] { 0x01, 0x10 };
            var payload = RandomNumberGenerator.GetBytes( 64 );
            var first = new byte[RunPhaseProtection.TagLength];
            var second = new byte[RunPhaseProtection.TagLength];

            i.SignNext( header, Seq( payload ), first ).ShouldBeTrue();
            i.SignNext( header, Seq( payload ), second ).ShouldBeTrue();

            second.ShouldNotBe( first,
                "Signing the same frame twice must produce different tags: the counter advances on " +
                "every call, so a nonce is never used twice regardless of what the caller does." );
        }
    }

    [TestCase( MacAlgorithm.AesGmac )]
    [TestCase( MacAlgorithm.HmacSha256 )]
    public void A_disposed_session_signs_nothing_and_verifies_nothing( MacAlgorithm alg )
    {
        // Teardown races with the send and receive loops, so the protection must report the
        // disposal rather than crash or — far worse — emit an unauthenticated frame.
        var (i, l) = MakePair( alg );
        var header = new byte[] { 0x01, 0x10 };
        var payload = RandomNumberGenerator.GetBytes( 32 );
        var tag = new byte[RunPhaseProtection.TagLength];
        i.SignNext( header, Seq( payload ), tag ).ShouldBeTrue();

        i.Dispose();
        l.Dispose();

        i.SignNext( header, Seq( payload ), tag ).ShouldBeFalse( "A disposed session must not sign." );
        l.VerifyNext( header, Seq( payload ), tag ).ShouldBeFalse( "A disposed session must not verify." );
        Should.NotThrow( () => i.Dispose(), "Dispose must be idempotent: teardown paths can overlap." );
    }

    [Test]
    public void The_counter_bound_is_enforced_rather_than_wrapped()
    {
        // Unreachable in practice (2^48 frames), which is exactly why it is checked: a wrapped
        // counter silently reuses nonces, and under GMAC that is a total break.
        RunPhaseProtection.MaxFrameCounter.ShouldBe( (1UL << 48) - 1 );

        var (i, _) = MakePair( MacAlgorithm.AesGmac );
        using( i )
        {
            SetSendCounter( i, RunPhaseProtection.MaxFrameCounter );
            var tag = new byte[RunPhaseProtection.TagLength];
            Should.Throw<InvalidOperationException>( () => i.SignNext( new byte[] { 0x01, 0x10 }, Seq( new byte[4] ), tag ),
                "At the bound the connection must stop rather than wrap into a reused nonce." );
        }
    }

    /// <summary>
    /// Drives the counter to a value that would take years to reach honestly.
    /// </summary>
    static void SetSendCounter( RunPhaseProtection p, ulong value )
    {
        var f = typeof( RunPhaseProtection ).GetField( "_sendCounter",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic );
        f.ShouldNotBeNull( "Field renamed? This test drives the counter directly." );
        f!.SetValue( p, value );
    }

    static (RunPhaseProtection Initiator, RunPhaseProtection Listener) MakePair( MacAlgorithm alg )
    {
        using var a = RunPhaseProtection.CreateEphemeral();
        using var b = RunPhaseProtection.CreateEphemeral();
        var transcript = RunPhaseProtection.BuildTranscript( RunPhaseProtection.LocalCapabilities, alg, 0,
                                                             "Test/$A/#Dev", "Test/$B/#Dev" );
        return (RunPhaseProtection.Derive( a, b.PublicKey.ExportSubjectPublicKeyInfo(), alg, 7, transcript, true ),
                RunPhaseProtection.Derive( b, a.PublicKey.ExportSubjectPublicKeyInfo(), alg, 7, transcript, false ));
    }
}
