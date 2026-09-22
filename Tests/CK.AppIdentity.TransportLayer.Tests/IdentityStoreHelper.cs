using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Reaching the identity key store of a test party from the outside.
/// <para>
/// These tests read back what was actually written rather than what the builder meant to write: the
/// stored certificate is what a peer validating a chain, or an OS trust store, will see.
/// </para>
/// </summary>
static class IdentityStoreHelper
{
    public static NormalizedPath GetKeysFolder( string partyName )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath
                .Combine( $"#Dev/Test/${partyName}/-Local/Keys" );

    public static string[] GetKeyFiles( string partyName )
    {
        var p = GetKeysFolder( partyName );
        return Directory.Exists( p )
                ? Directory.EnumerateFiles( p, "*.pfx" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    public static void ClearKeys( string partyName )
    {
        var p = GetKeysFolder( partyName );
        if( Directory.Exists( p ) ) Directory.Delete( p, recursive: true );
    }

    // The parameter is typed IDataProtectionProvider so that AddSingleton infers THAT service type:
    // the test helper already registered a FakeProtector for it and the last registration wins.
    public static Task<ApplicationIdentityService> CreateAsync( string partyName,
                                                                IDataProtectionProvider protector,
                                                                CancellationToken token )
        => TestHelper.CreateApplicationServiceAsync(
                c => c["FullName"] = $"Test/${partyName}",
                services => services.AddSingleton( protector ),
                token );

    /// <summary>
    /// Loads a stored identity. The PFX password lives in the protected <c>.pwd</c> side file, so
    /// this needs the very protector the service was given.
    /// </summary>
    public static X509Certificate2 LoadStoredCertificate( string partyName, IDataProtector protector, string fileName )
    {
        var pfx = GetKeysFolder( partyName ).AppendPart( fileName );
        var pwd = Encoding.UTF8.GetString( protector.Unprotect( File.ReadAllBytes( pfx + ".pwd" ) ) );
        return new X509Certificate2( File.ReadAllBytes( pfx ), pwd );
    }

    /// <summary>
    /// Loads the single stored identity of a party, failing the test if there is not exactly one.
    /// </summary>
    public static X509Certificate2 LoadTheStoredCertificate( string partyName, IDataProtector protector )
    {
        var files = GetKeyFiles( partyName );
        files.Length.ShouldBe( 1 );
        return LoadStoredCertificate( partyName, protector, files[0] );
    }

    public static T GetExtension<T>( X509Certificate2 c ) where T : X509Extension
        => c.Extensions.OfType<T>().SingleOrDefault()
           ?? throw new AssertionException( $"No {typeof( T ).Name} on '{c.Subject}'." );
}
