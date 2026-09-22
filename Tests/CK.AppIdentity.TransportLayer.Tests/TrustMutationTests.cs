using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M15: the trusted key of a remote was mutated without synchronization.
/// <para>
/// <c>_identity</c> is written from back tasks, each on its own thread, and the write is the tail of a
/// read-compare-write that also creates and trashes the <c>.public</c> file mirroring it. The state
/// and the file have to change together, and nothing made them.
/// </para>
/// <para>
/// The damage outlives the process: what the next start reads is the set of <c>.public</c> files. A
/// remote left with two of them, or with one that does not match what is trusted in memory, is a
/// trust decision corrupted on disk.
/// </para>
/// </summary>
[TestFixture]
public class TrustMutationTests
{
    readonly SystemClockTester _systemClock = new SystemClockTester( 50 );

    void ConfigureFastClock( ServiceCollection services )
        => services.AddSingleton<ApplicationIdentityService.ISystemClock>( _systemClock );

    static RemoteIdentityKeyData NewKeyData( DateTime timeName )
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.KeySize = 256;
        var req = new CertificateRequest( "CN=Rotation", ecdsa, HashAlgorithmName.SHA256 );
        using var cert = req.CreateSelfSigned( DateTimeOffset.UtcNow.AddDays( -1 ), DateTimeOffset.UtcNow.AddDays( 30 ) );
        return new RemoteIdentityKeyData( timeName, cert.PublicKey );
    }

    static string[] PublicFiles( IRemoteKeys keys )
    {
        var folder = keys.Party.SharedFileStore.FolderPath;
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, "Identity.*.public" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    async Task<(ApplicationIdentityService Service, IRemoteKeys Keys)> CreateRemoteAsync( string name, CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = $"${name}Peer";
        }, ConfigureFastClock, token: token );
        return (s, s.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>());
    }

    [Test, CancelAfter( 120000 )]
    public async Task Concurrent_trust_updates_leave_one_key_on_disk_Async( CancellationToken token )
    {
        // The finding, hammered. Several threads rotate the same remote between a handful of keys at
        // once — which is what two connections negotiating through a key change do. However the races
        // fall, the store must end with exactly one identity file and it must be the trusted one.
        //
        // Unsynchronized, SaveDifferingKey reads the current key, writes the new file and trashes the
        // old one while another thread is doing the same from the same starting point: both files
        // survive, or the one that ends up trusted is the one that was trashed.
        var (service, keys) = await CreateRemoteAsync( "M15Race", token );
        await using var _svc = service;

        var rotation = Enumerable.Range( 0, 6 )
                                 .Select( i => NewKeyData( DateTime.UtcNow.AddMinutes( -60 + i ) ) )
                                 .ToArray();

        using var start = new ManualResetEventSlim( false );
        var workers = Enumerable.Range( 0, 6 ).Select( w => Task.Run( () =>
        {
            start.Wait( token );
            for( int i = 0; i < 60; ++i )
            {
                keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, rotation[(w + i) % rotation.Length] );
            }
        }, token ) ).ToArray();

        start.Set();
        await Task.WhenAll( workers );

        var trusted = keys.TrustedIdentity;
        trusted.ShouldNotBeNull();
        var files = PublicFiles( keys );
        files.Length.ShouldBe( 1,
            $"Exactly one identity file must survive, got [{string.Join( ", ", files )}]. More than one " +
            "means two threads each wrote theirs and trashed the other's starting point; the next " +
            "start would then have to guess which key this remote is." );
        files[0].ShouldBe( $"Identity.{trusted!.Name}.public",
            "And the survivor must be the key that is actually trusted, not one that was trashed." );

        var onDisk = File.ReadAllBytes( keys.Party.SharedFileStore.FolderPath.AppendPart( files[0] ) );
        onDisk.ShouldBe( trusted.PublicKeyRawData.ToArray(), "The file must hold the trusted key's bytes." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Setting_the_same_key_again_changes_nothing_Async( CancellationToken token )
    {
        // The idempotence SaveDifferingKey relies on: OnReadIdentityKeys runs on every connection, so
        // if re-setting an unchanged key rewrote and re-trashed files, the store would churn on every
        // handshake.
        var (service, keys) = await CreateRemoteAsync( "M15Idem", token );
        await using var _svc = service;

        var k = NewKeyData( DateTime.UtcNow.AddMinutes( -10 ) );
        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, k ).ShouldBeTrue( "First set." );
        var files = PublicFiles( keys );
        files.Length.ShouldBe( 1 );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, k ).ShouldBeFalse( "Same key: nothing to do." );
        PublicFiles( keys ).ShouldBe( files );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Clearing_the_trusted_key_removes_its_file_Async( CancellationToken token )
    {
        var (service, keys) = await CreateRemoteAsync( "M15Clear", token );
        await using var _svc = service;

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, NewKeyData( DateTime.UtcNow.AddMinutes( -10 ) ) ).ShouldBeTrue();
        PublicFiles( keys ).Length.ShouldBe( 1 );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, (RemoteIdentityKeyData?)null ).ShouldBeTrue();
        keys.TrustedIdentity.ShouldBeNull();
        PublicFiles( keys ).ShouldBeEmpty( "A remote with no trusted key must leave no identity file behind." );
    }
}
