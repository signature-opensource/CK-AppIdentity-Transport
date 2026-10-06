using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer.Testing.Adversarial;
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
/// Finding M15: the trusted identity of a remote was mutated without synchronization.
/// <para>
/// The pin is written from back tasks, each on its own thread, and the write is the tail of a
/// read-compare-write that also creates and trashes the <c>Identity.{Seq}.trust</c> file mirroring
/// it. The state and the file have to change together.
/// </para>
/// <para>
/// The damage outlives the process: what the next start reads is the set of <c>.trust</c> files. A
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

    static string[] TrustFiles( IRemoteKeys keys )
    {
        var folder = keys.Party.SharedFileStore.FolderPath;
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, "Identity.*.trust" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    static KeyEvent OnDisk( IRemoteKeys keys, string file )
        => KeyEvent.Read( File.ReadAllBytes( keys.Party.SharedFileStore.FolderPath.AppendPart( file ) ) );

    async Task<(ApplicationIdentityService Service, IRemoteKeys Keys, string RemoteFullName)> CreateRemoteAsync( string name, CancellationToken token )
    {
        PeerStore.ClearRemoteTrust( $"Test/${name}Peer" );
        var s = await TestHelper.CreateApplicationServiceAsync( c =>
        {
            c["FullName"] = $"Test/${name}";
            c["Parties:0:PartyName"] = $"${name}Peer";
        }, ConfigureFastClock, token: token );
        return (s, s.AllRemotes.Single().GetRequiredFeature<IRemoteKeys>(), $"Test/${name}Peer/#Dev");
    }

    [Test, CancelAfter( 120000 )]
    public async Task Concurrent_trust_updates_leave_one_pin_on_disk_Async( CancellationToken token )
    {
        // The finding, hammered. Several threads move the same remote between the events of its log at
        // once - forward through ApplyTail as a handshake does, and anywhere through SetTrustedIdentity
        // as an operator does. However the races fall, the store must end with exactly one pin file
        // and it must be the pinned event.
        var (service, keys, remote) = await CreateRemoteAsync( "M15Race", token );
        await using var _svc = service;

        using var peer = PeerIdentity.Create( remote );
        for( int i = 0; i < 5; ++i ) peer.Rotate();
        var events = peer.Events.ToArray();

        using var start = new ManualResetEventSlim( false );
        var workers = Enumerable.Range( 0, 6 ).Select( w => Task.Run( () =>
        {
            start.Wait( token );
            for( int i = 0; i < 60; ++i )
            {
                if( (w + i) % 2 == 0 )
                {
                    keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, events[(w + i) % events.Length] );
                }
                else
                {
                    keys.ApplyTail( TestHelper.Monitor.ParallelLogger, events );
                }
            }
        }, token ) ).ToArray();

        start.Set();
        await Task.WhenAll( workers );

        var pinned = keys.TrustedEvent;
        pinned.ShouldNotBeNull();
        var files = TrustFiles( keys );
        files.Length.ShouldBe( 1,
            $"Exactly one pin file must survive, got [{string.Join( ", ", files )}]. More than one " +
            "means two threads each wrote theirs and trashed the other's starting point; the next " +
            "start would then have to guess which identity this remote is." );
        files[0].ShouldBe( $"Identity.{pinned!.Seq}.trust",
            "And the survivor must be the pinned event, not one that was trashed." );
        OnDisk( keys, files[0] ).GetDigest( remote ).ToArray().ShouldBe( pinned.GetDigest( remote ).ToArray(),
            "The file must hold the pinned event." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Setting_the_same_event_again_changes_nothing_Async( CancellationToken token )
    {
        // Every handshake applies the tail it receives: if re-pinning an unchanged event rewrote and
        // re-trashed files, the store would churn on every connection.
        var (service, keys, remote) = await CreateRemoteAsync( "M15Idem", token );
        await using var _svc = service;

        using var peer = PeerIdentity.Create( remote );
        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, peer.Head ).ShouldBeTrue( "First set." );
        var files = TrustFiles( keys );
        files.Length.ShouldBe( 1 );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, peer.Head ).ShouldBeFalse( "Same event: nothing to do." );
        keys.ApplyTail( TestHelper.Monitor.ParallelLogger, peer.Tail ).Verdict.ShouldBe( KeyChainVerdict.UpToDate );
        TrustFiles( keys ).ShouldBe( files );
    }

    [Test, CancelAfter( 60000 )]
    public async Task Clearing_the_pin_removes_its_file_Async( CancellationToken token )
    {
        var (service, keys, remote) = await CreateRemoteAsync( "M15Clear", token );
        await using var _svc = service;

        using var peer = PeerIdentity.Create( remote );
        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, peer.Head ).ShouldBeTrue();
        TrustFiles( keys ).Length.ShouldBe( 1 );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, null ).ShouldBeTrue();
        keys.TrustedIdentity.ShouldBeNull();
        keys.TrustedEvent.ShouldBeNull();
        TrustFiles( keys ).ShouldBeEmpty( "A remote with nothing pinned must leave no pin file behind." );
    }

    [Test, CancelAfter( 60000 )]
    public async Task An_event_at_the_same_sequence_keeps_its_file_on_disk_Async( CancellationToken token )
    {
        // Finding M1, as it now reads. The file name is the sequence alone, but two different events
        // can share a sequence (two identities of the same name, each at its inception). Replacing one
        // by the other maps to the very same file: writing the new one then trashing "the old one"
        // would leave the remote pinned in memory and with NO file at all - the next start would find
        // nothing pinned, dead under AutoTrustKey.Never and silently re-TOFUing under Once.
        var (service, keys, remote) = await CreateRemoteAsync( "M1SameSeq", token );
        await using var _svc = service;

        using var first = PeerIdentity.Create( remote );
        using var second = PeerIdentity.Create( remote );
        first.Head.Seq.ShouldBe( second.Head.Seq );
        first.HeadDigest.ShouldNotBe( second.HeadDigest, "But they are different events." );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, first.Head ).ShouldBeTrue( "First set." );
        TrustFiles( keys ).Length.ShouldBe( 1 );

        keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, second.Head ).ShouldBeTrue( "A different event: a real change." );

        var files = TrustFiles( keys );
        files.Length.ShouldBe( 1, "Exactly one pin file must remain - not zero." );
        OnDisk( keys, files[0] ).GetDigest( remote ).ToArray().ShouldBe( second.HeadDigest,
            "And it must hold the event that is now pinned, not the one it replaced." );
        keys.TrustedIdentity!.PublicKeyRawData.ToArray().ShouldBe( second.SubjectPublicKeyInfo );
    }

    [Test, CancelAfter( 60000 )]
    public async Task An_event_signed_for_another_party_cannot_be_pinned_Async( CancellationToken token )
    {
        // The operator path checks the one thing an isolated event can prove: it is signed, by the key
        // it reveals, for THIS remote's name.
        var (service, keys, remote) = await CreateRemoteAsync( "PinOther", token );
        await using var _svc = service;

        using var someoneElse = PeerIdentity.Create( "Test/$SomeoneElse/#Dev" );
        Should.Throw<ArgumentException>( () => keys.SetTrustedIdentity( TestHelper.Monitor.ParallelLogger, someoneElse.Head ) );
        keys.TrustedEvent.ShouldBeNull();
    }
}
