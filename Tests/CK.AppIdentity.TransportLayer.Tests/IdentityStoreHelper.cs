using CK.AppIdentity.KeyManagement;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using NUnit.Framework;
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
/// Reaching the identity of a test party from the outside.
/// <para>
/// These tests read back what was actually written rather than what the builder meant to write: the
/// stored certificate is what a peer validating a chain, or an OS trust store, will see.
/// </para>
/// <para>
/// Layout: <c>-Local/Keys/Current.cer</c> (public), <c>-Local/Keys/Kel/{Seq}.event</c> (the key event
/// log) and, for the <see cref="DefaultCoreKeyStore"/>, <c>-Local/CoreKeys/{Seq}.key</c>.
/// </para>
/// </summary>
static class IdentityStoreHelper
{
    /// <summary>
    /// The full name of a test party: the configured name in the default "#Dev" domain.
    /// </summary>
    public static string FullName( string partyName ) => $"Test/${partyName}/#Dev";

    static NormalizedPath GetLocalFolder( string partyName )
        => ApplicationIdentityServiceConfiguration.DefaultStoreRootPath.Combine( $"#Dev/Test/${partyName}/-Local" );

    public static NormalizedPath GetKeysFolder( string partyName ) => GetLocalFolder( partyName ).AppendPart( "Keys" );

    public static NormalizedPath GetCurrentCertificatePath( string partyName ) => GetKeysFolder( partyName ).AppendPart( "Current.cer" );

    public static NormalizedPath GetKelFolder( string partyName ) => GetKeysFolder( partyName ).AppendPart( "Kel" );

    public static NormalizedPath GetCoreKeysFolder( string partyName ) => GetLocalFolder( partyName ).AppendPart( DefaultCoreKeyStore.FolderName );

    /// <summary>
    /// The names of the private keys held by the default store, sorted.
    /// </summary>
    public static string[] GetKeyNames( string partyName )
    {
        var p = GetCoreKeysFolder( partyName );
        return Directory.Exists( p )
                ? Directory.EnumerateFiles( p, "*.key" ).Select( f => Path.GetFileNameWithoutExtension( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    /// <summary>
    /// The names of the event files of the log, sorted.
    /// </summary>
    public static string[] GetEventFiles( string partyName )
    {
        var p = GetKelFolder( partyName );
        return Directory.Exists( p )
                ? Directory.EnumerateFiles( p, "*.event" ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    /// <summary>
    /// Resets a party's identity: its <c>Keys</c> folder and its default key store.
    /// </summary>
    public static void ClearKeys( string partyName )
    {
        foreach( var p in new[] { GetKeysFolder( partyName ), GetCoreKeysFolder( partyName ) } )
        {
            if( Directory.Exists( p ) ) Directory.Delete( p, recursive: true );
        }
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
    /// Loads the stored identity certificate. It is public data: no protector is needed.
    /// </summary>
    public static X509Certificate2 LoadCurrentCertificate( string partyName )
        => X509CertificateLoader.LoadCertificate( File.ReadAllBytes( GetCurrentCertificatePath( partyName ) ) );

    /// <summary>
    /// Opens a private key of a running party through the store it uses.
    /// </summary>
    public static ECDsa OpenKey( ApplicationIdentityService running, IDataProtectionProvider protector, int seq )
        => new DefaultCoreKeyStore( protector ).OpenKey( TestHelper.Monitor, running, seq.ToString() )
           ?? throw new AssertionException( $"Key #{seq} cannot be opened." );

    /// <summary>
    /// Replaces the stored <c>Current.cer</c> by a certificate of <paramref name="key"/> with the given
    /// profile, so that the loader's verdict on exactly one property can be observed.
    /// </summary>
    public static void WriteCurrentCertificate( string partyName,
                                                ECDsa key,
                                                DateTime notAfterUtc,
                                                bool certificateAuthority = true,
                                                string? commonName = null )
    {
        var request = new CertificateRequest( $"CN={commonName ?? FullName( partyName )}", key, HashAlgorithmName.SHA256 );
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension( X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true ) );
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension( certificateAuthority, certificateAuthority, 0, true ) );
        request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, false ) );
        // NotBefore is back-dated a day exactly as the builder does.
        using var c = request.CreateSelfSigned( new DateTimeOffset( DateTime.UtcNow.AddDays( -1 ) ), new DateTimeOffset( notAfterUtc ) );
        File.WriteAllBytes( GetCurrentCertificatePath( partyName ), c.Export( X509ContentType.Cert ) );
    }

    public static T GetExtension<T>( X509Certificate2 c ) where T : X509Extension
        => c.Extensions.OfType<T>().SingleOrDefault()
           ?? throw new AssertionException( $"No {typeof( T ).Name} on '{c.Subject}'." );
}
