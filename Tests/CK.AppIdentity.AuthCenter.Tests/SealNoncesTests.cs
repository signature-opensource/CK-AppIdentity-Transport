using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.AuthCenter.Tests;

[TestFixture]
public class SealNoncesTests
{
    [Test]
    public async Task a_used_seal_stays_used_after_a_restart_Async()
    {
        await using var app = await AuthCenterApp.StartAsync();
        var store = app.Identity.LocalFileStore;
        var path = store.FolderPath.Combine( "Tests/SealNonces.journal" );
        if( File.Exists( path ) ) File.Delete( path );
        var utcNow = DateTime.UtcNow;
        var expires = utcNow + RoutedCommandSeal.Lifetime + RoutedCommandSeal.ClockSkew;

        var nonces = new AuthCenterSealNonces( TestHelper.Monitor, store, path, utcNow );
        nonces.TryUse( TestHelper.Monitor, "A1", expires, utcNow ).ShouldBeTrue();
        nonces.TryUse( TestHelper.Monitor, "A1", expires, utcNow ).ShouldBeFalse( "Used once." );
        nonces.TryUse( TestHelper.Monitor, "B2", utcNow.AddSeconds( 1 ), utcNow ).ShouldBeTrue();

        // A restart (or a crash: every nonce is flushed before it is accepted) forgets nothing that is still alive.
        var restarted = new AuthCenterSealNonces( TestHelper.Monitor, store, path, utcNow );
        restarted.TryUse( TestHelper.Monitor, "A1", expires, utcNow ).ShouldBeFalse();
        restarted.TryUse( TestHelper.Monitor, "B2", utcNow.AddSeconds( 1 ), utcNow ).ShouldBeFalse();

        // A torn record at the end of the journal is ignored.
        using( var f = new FileStream( path, FileMode.Append ) ) f.Write( [1, 2, 3] );
        var afterCrash = new AuthCenterSealNonces( TestHelper.Monitor, store, path, utcNow );
        afterCrash.Count.ShouldBe( 2 );

        // The expired ones are dropped, and the journal is rewritten without them.
        var later = utcNow.AddSeconds( 2 );
        afterCrash.Compact( TestHelper.Monitor, later );
        afterCrash.Count.ShouldBe( 1 );
        new AuthCenterSealNonces( TestHelper.Monitor, store, path, later ).Count.ShouldBe( 1 );
        afterCrash.TryUse( TestHelper.Monitor, "B2", later.AddMinutes( 1 ), later ).ShouldBeTrue( "Expired: forgotten." );
        File.Delete( path );
    }
}
