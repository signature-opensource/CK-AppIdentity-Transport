using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
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
/// Finding M1: the handshake nonce replay cache.
/// <para>
/// A nonce makes a handshake single-use. The clock window bounds how long a captured message stays
/// replayable; this cache is what stops a replay inside that window.
/// </para>
/// <para>
/// One ring shared by every remote of a local party would be weaker than it looks: any remote's
/// handshakes then evict every other remote's nonces. That is not only an attack. The reconnect
/// back-off caps at one attempt per second, so a handful of flapping remotes wrap a thousand slots
/// in about five minutes — the same order as the window the cache must cover. The protection
/// would degrade as remotes are added, silently.
/// </para>
/// </summary>
[TestFixture]
public class NonceCacheTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static TimedNonce Nonce( DateTime now, ulong? value = null )
        => new TimedNonce( now, value ?? BitConverter.ToUInt64( RandomNumberGenerator.GetBytes( 8 ) ) );

    /// <summary>
    /// Two remotes of one local party. The caller must dispose the service: leaving it running
    /// holds the listening port and the remotes' store folders, which breaks every later test.
    /// Remote names are derived from <paramref name="local"/> for the same reason — the store is
    /// keyed by remote name and is shared across local parties.
    /// </summary>
    async Task<(ApplicationIdentityService Service, IRemoteKeys A, IRemoteKeys B)> TwoRemotesAsync( string local,
                                                                                                    CancellationToken token )
    {
        var nameA = $"${local}A";
        var nameB = $"${local}B";
        // The cache is PERSISTED, so a second run would load the entries these tests expect to be
        // absent. Start from a clean store, exactly as the trust-store tests have to.
        PeerStore.ClearLocalParty( $"Test/${local}" );
        PeerStore.ClearRemoteTrust( $"Test/{nameA}" );
        PeerStore.ClearRemoteTrust( $"Test/{nameB}" );
        var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${local}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = nameA;
            c["Parties:1:PartyName"] = nameB;
        }, ConfigureFastClock, token: token );
        var remotes = s.AllRemotes.ToArray();
        remotes.Length.ShouldBe( 2 );
        var a = remotes.Single( r => r.PartyName == nameA ).GetRequiredFeature<IRemoteKeys>();
        var b = remotes.Single( r => r.PartyName == nameB ).GetRequiredFeature<IRemoteKeys>();
        return (s, a, b);
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_nonce_is_single_use_per_remote_Async( CancellationToken token )
    {
        var (service, a, _) = await TwoRemotesAsync( "NonceSingle", token );
        await using var _svc = service;
        var n = Nonce( _systemClock.UtcNow );

        a.CheckAndAddNonceValue( TestHelper.Monitor, n ).ShouldBeTrue( "First use." );
        a.CheckAndAddNonceValue( TestHelper.Monitor, n, LogLevel.None ).ShouldBeFalse(
            "The same nonce from the same remote is a replay." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Nonces_are_partitioned_per_remote_Async( CancellationToken token )
    {
        // Two remotes are independent namespaces. Sharing one meant a nonce spent by A could make
        // B's identical nonce look like a replay — and, far more importantly, that A's traffic
        // evicted B's entries.
        var (service, a, b) = await TwoRemotesAsync( "NoncePart", token );
        await using var _svc = service;
        var n = Nonce( _systemClock.UtcNow );

        a.CheckAndAddNonceValue( TestHelper.Monitor, n ).ShouldBeTrue();
        b.CheckAndAddNonceValue( TestHelper.Monitor, n ).ShouldBeTrue(
            "The same value from a DIFFERENT remote is not a replay: the partitions are separate." );
        b.CheckAndAddNonceValue( TestHelper.Monitor, n, LogLevel.None ).ShouldBeFalse(
            "But it is spent for that remote now." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task One_remote_cannot_evict_another_remotes_nonces_Async( CancellationToken token )
    {
        // The finding, directly. Remote B records one nonce; remote A then floods far past the old
        // 1023-slot shared ring. B's nonce must still be remembered.
        var (service, a, b) = await TwoRemotesAsync( "NonceEvict", token );
        await using var _svc = service;
        var now = _systemClock.UtcNow;

        var bNonce = Nonce( now );
        b.CheckAndAddNonceValue( TestHelper.Monitor, bNonce ).ShouldBeTrue();

        // Comfortably more than any plausible shared capacity, and more than this remote's own guard, so
        // A also sheds its own oldest entries — which must not touch B.
        for( int i = 0; i < IRemoteKeys.MaxNonceCacheEntries + 2000; ++i )
        {
            a.CheckAndAddNonceValue( TestHelper.Monitor, Nonce( now, (ulong)(i + 1) ), LogLevel.None ).ShouldBeTrue();
        }

        b.CheckAndAddNonceValue( TestHelper.Monitor, bNonce, LogLevel.None ).ShouldBeFalse(
            "B's nonce must still be known after A flooded. With one shared ring it would have been " +
            "evicted, and replaying B's captured handshake would have succeeded." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_nonce_outside_the_clock_window_is_forgotten_Async( CancellationToken token )
    {
        // Bounded by time rather than by count: an entry is dropped only once it can no longer be
        // replayed at all, which is exactly when the timestamp check would reject it anyway.
        var (service, a, _) = await TwoRemotesAsync( "NonceWindow", token );
        await using var _svc = service;
        var now = _systemClock.UtcNow;

        // A nonce created well before the window: recording it is harmless, and it must not be
        // retained once newer traffic moves the window on.
        var old = Nonce( now - a.MaxClockOffset - TimeSpan.FromMinutes( 1 ) );
        a.CheckAndAddNonceValue( TestHelper.Monitor, old ).ShouldBeTrue();

        // Any later handshake prunes what has aged out.
        a.CheckAndAddNonceValue( TestHelper.Monitor, Nonce( now ) ).ShouldBeTrue();

        a.CheckAndAddNonceValue( TestHelper.Monitor, old ).ShouldBeTrue(
            "An entry older than the window is dropped: it can no longer be replayed, because the " +
            "clock-offset check rejects it on its timestamp." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task A_nonce_survives_a_restart_Async( CancellationToken token )
    {
        // The cache is persisted so a restart cannot be used to forget a nonce and replay a
        // captured handshake. This also pins that shutting down is NOT treated as destroying the
        // party: the record must outlive the process but not the remote.
        const string local = "NoncePersist";
        var n = Nonce( _systemClock.UtcNow );

        var (service, a, _) = await TwoRemotesAsync( local, token );
        a.CheckAndAddNonceValue( TestHelper.Monitor, n ).ShouldBeTrue();
        await service.DisposeAsync();

        // Same store, fresh process. TwoRemotesAsync clears the store, so rebuild by hand.
        await using var restarted = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${local}";
            c["AlwaysListening"] = "True";
            c["Parties:0:PartyName"] = $"${local}A";
            c["Parties:1:PartyName"] = $"${local}B";
        }, ConfigureFastClock, token: token );

        var a2 = restarted.AllRemotes.Single( r => r.PartyName == $"${local}A" ).GetRequiredFeature<IRemoteKeys>();
        a2.CheckAndAddNonceValue( TestHelper.Monitor, n, LogLevel.None ).ShouldBeFalse(
            "A nonce spent before the restart must still be known: otherwise restarting is enough " +
            "to forget it and replay a captured handshake inside the clock window." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Each_local_party_keeps_its_own_record_of_a_remote_Async( CancellationToken token )
    {
        // The remote's folder is shared by every local party on this file system, so the cache is
        // named by the local party inside it. The separation is for WRITERS — several processes
        // sharing one file would corrupt it — not for secrecy.
        var (service, a, _) = await TwoRemotesAsync( "NonceScope", token );
        await using var _svc = service;

        var expected = ApplicationIdentityServiceConfiguration.DefaultStoreRootPath
                            .Combine( "#Dev/Test/$NonceScopeA/-Locals/Test/$NonceScope/#Dev/Nonce.cache" );
        a.CheckAndAddNonceValue( TestHelper.Monitor, Nonce( _systemClock.UtcNow ) ).ShouldBeTrue();
        await service.DisposeAsync();

        System.IO.File.Exists( expected ).ShouldBeTrue(
            $"The cache must live under the remote's folder, scoped by the local party: '{expected}'." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task The_memory_guard_degrades_only_the_offending_remote_Async( CancellationToken token )
    {
        // Time-bounding alone would let a peer handshaking absurdly fast grow memory without limit
        // inside the window, so there is still a per-remote cap. Reaching it must cost that remote
        // its oldest entries and nobody else's.
        var (service, a, b) = await TwoRemotesAsync( "NonceGuard", token );
        await using var _svc = service;
        var now = _systemClock.UtcNow;

        var first = Nonce( now, 1 );
        a.CheckAndAddNonceValue( TestHelper.Monitor, first ).ShouldBeTrue();
        var bNonce = Nonce( now, 7777 );
        b.CheckAndAddNonceValue( TestHelper.Monitor, bNonce ).ShouldBeTrue();

        for( int i = 0; i < IRemoteKeys.MaxNonceCacheEntries + 10; ++i )
        {
            a.CheckAndAddNonceValue( TestHelper.Monitor, Nonce( now, (ulong)(i + 100) ), LogLevel.None ).ShouldBeTrue();
        }

        a.CheckAndAddNonceValue( TestHelper.Monitor, first ).ShouldBeTrue(
            "A's oldest entry was shed to honour the memory guard." );
        b.CheckAndAddNonceValue( TestHelper.Monitor, bNonce, LogLevel.None ).ShouldBeFalse(
            "B is untouched: the degradation is confined to the remote that caused it." );
    }
}
