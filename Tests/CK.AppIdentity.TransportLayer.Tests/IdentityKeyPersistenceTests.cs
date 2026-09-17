using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Covers the identity key store round-trip across restarts.
/// <para>
/// This was never exercised: the creation path validates the in-memory certificate, never a reload
/// from disk, and the only <see cref="IDataProtector"/> used by the tests was the identity
/// <see cref="FakeProtector"/>, under which a Protect/Unprotect overload mismatch cancels itself out.
/// With a protector that actually protects (<see cref="HeaderProtector"/>), a mismatch trashes every
/// stored identity on every start.
/// </para>
/// </summary>
[TestFixture]
public class IdentityKeyPersistenceTests
{
    static NormalizedPath GetKeysFolder( string partyName )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath
                .Combine( $"#Dev/Test/${partyName}/-Local/Keys" );

    static string[] GetKeyFiles( string partyName )
    {
        var p = GetKeysFolder( partyName );
        return Directory.Exists( p )
                ? Directory.EnumerateFiles( p, "*.pfx" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : System.Array.Empty<string>();
    }

    static Task<ApplicationIdentityService> CreateAsync( string partyName, IDataProtectionProvider protector, CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync(
                c => c["FullName"] = $"Test/${partyName}",
                services => services.AddSingleton( protector ),
                token );

    [CancelAfter( 20000 )]
    [Test]
    public async Task Identity_keys_survive_a_restart_with_a_real_protector_Async( CancellationToken token )
    {
        const string partyName = "KeyPersistReal";
        var keysFolder = GetKeysFolder( partyName );
        if( Directory.Exists( keysFolder ) ) Directory.Delete( keysFolder, recursive: true );

        var protector = new HeaderProtector();

        // First start: no key exists, one is created.
        await using( await CreateAsync( partyName, protector, token ) )
        {
        }
        var afterFirstStart = GetKeyFiles( partyName );
        afterFirstStart.Length.ShouldBe( 1, "The first start creates exactly one identity key." );

        // Second start over the same store: the key must be READ BACK, not trashed and recreated.
        await using( await CreateAsync( partyName, protector, token ) )
        {
        }
        var afterSecondStart = GetKeyFiles( partyName );
        afterSecondStart.ShouldBe( afterFirstStart,
                                   "The stored identity key must be reloaded across restarts: if the .pwd side file " +
                                   "cannot be unprotected, the key is trashed and a new one is created, and every " +
                                   "remote that pinned the previous key needs a new approval after every restart." );

        // And a third one, to be sure nothing accumulates either.
        await using( await CreateAsync( partyName, protector, token ) )
        {
        }
        GetKeyFiles( partyName ).ShouldBe( afterFirstStart );
    }

    [CancelAfter( 20000 )]
    [Test]
    public async Task Identity_keys_survive_a_restart_with_the_FakeProtector_Async( CancellationToken token )
    {
        const string partyName = "KeyPersistFake";
        var keysFolder = GetKeysFolder( partyName );
        if( Directory.Exists( keysFolder ) ) Directory.Delete( keysFolder, recursive: true );

        await using( await CreateAsync( partyName, FakeProtector.Fake, token ) )
        {
        }
        var afterFirstStart = GetKeyFiles( partyName );
        afterFirstStart.Length.ShouldBe( 1 );

        await using( await CreateAsync( partyName, FakeProtector.Fake, token ) )
        {
        }
        GetKeyFiles( partyName ).ShouldBe( afterFirstStart );
    }

    [Test]
    public void HeaderProtector_round_trips_and_rejects_foreign_payloads()
    {
        var p = new HeaderProtector();
        var clear = new byte[] { 1, 2, 3, 4, 5 };
        p.Unprotect( p.Protect( clear ) ).ShouldBe( clear );
        // This is what the broken code did: hand back something this protector never produced.
        Should.Throw<System.Security.Cryptography.CryptographicException>( () => p.Unprotect( clear ) );
    }
}
