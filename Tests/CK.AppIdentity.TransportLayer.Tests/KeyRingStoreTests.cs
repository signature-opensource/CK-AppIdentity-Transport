using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// <see cref="KeyRingStore"/>: the DataProtection key ring of the process lives in the private store of the root party,
/// protected by the secret key of its configuration, the CNG store, DPAPI (Windows) or nothing. The real DataProtection
/// protects the identity keys here (the test helper's <see cref="FakeProtector"/> is replaced).
/// </summary>
[TestFixture]
public class KeyRingStoreTests
{
    const string SoftwareProvider = "Microsoft Software Key Storage Provider";

    static NormalizedPath GetKeyRingFolder( string partyName )
        => IdentityStoreHelper.GetCoreKeysFolder( partyName ).RemoveLastPart().AppendPart( KeyRingStore.FolderName );

    static string[] GetKeyRingFiles( string partyName )
    {
        var folder = GetKeyRingFolder( partyName );
        return Directory.Exists( folder ) ? Directory.GetFiles( folder, "*.xml" ).Order().ToArray() : Array.Empty<string>();
    }

    static void Clear( string partyName )
    {
        IdentityStoreHelper.ClearKeys( partyName );
        var ring = GetKeyRingFolder( partyName );
        if( Directory.Exists( ring ) ) Directory.Delete( ring, recursive: true );
    }

    static string NewSecretKey() => Convert.ToBase64String( RandomNumberGenerator.GetBytes( 32 ) );

    // A party whose identity keys are protected by the real DataProtection, with the key ring of KeyManagementDataProtection.
    static Task<ApplicationIdentityService> CreateAsync( string partyName,
                                                         CancellationToken token,
                                                         Action<MutableConfigurationSection>? configure = null,
                                                         Action<IDataProtectionBuilder>? dataProtection = null,
                                                         bool cng = false )
        => TestHelper.CreateApplicationServiceAsync(
                c =>
                {
                    c["FullName"] = $"Test/${partyName}";
                    configure?.Invoke( c );
                },
                services =>
                {
                    services.RemoveAll<IDataProtectionProvider>();
                    var b = services.AddDataProtection();
                    dataProtection?.Invoke( b );
                    KeyRingStore.Register( services );
                    if( cng )
                    {
                        services.AddSingleton<ICoreKeyStore>( sp => new CngCoreKeyStore( sp.GetRequiredService<DefaultCoreKeyStore>(), sp ) );
                        services.AddPartyComponentOptions( [typeof( CngKeyStoreOption )] );
                    }
                },
                token );

    static string CurrentKey( ApplicationIdentityService s ) => Convert.ToHexString( s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.Span );

    static XElement LoadSingleKeyRingFile( string partyName )
    {
        var files = GetKeyRingFiles( partyName );
        files.Length.ShouldBe( 1, "One key in the ring." );
        return XElement.Load( files[0] );
    }

    // The encrypted secrets of a key of the ring (in the namespace of the DataProtection).
    static System.Collections.Generic.IEnumerable<XElement> EncryptedSecrets( XElement key ) => key.Descendants().Where( e => e.Name.LocalName == "encryptedSecret" );

    // The type of the decryptor of the (only) key of the ring; null when it is not encrypted.
    static string? GetDecryptorType( XElement key ) => (string?)EncryptedSecrets( key ).SingleOrDefault()?.Attribute( "decryptorType" );

    [Test, CancelAfter( 30000 )]
    public async Task The_key_ring_is_in_the_store_of_the_party_and_the_identity_survives_a_restart_Async( CancellationToken token )
    {
        const string partyName = "KeyRingDefault";
        Clear( partyName );
        string current;
        await using( var s = await CreateAsync( partyName, token ) )
        {
            current = CurrentKey( s );
        }
        var key = LoadSingleKeyRingFile( partyName );
        if( OperatingSystem.IsWindows() )
        {
            GetDecryptorType( key ).ShouldNotBeNull().ShouldContain( "DpapiXmlDecryptor", customMessage: "On Windows, DPAPI by default." );
        }
        else
        {
            GetDecryptorType( key ).ShouldNotBeNull().ShouldContain( "NullXmlDecryptor", customMessage: "Elsewhere, no encryption by default." );
        }
        await using( var s = await CreateAsync( partyName, token ) )
        {
            CurrentKey( s ).ShouldBe( current, "The identity keys are read back with the key ring of the store." );
        }
        GetKeyRingFiles( partyName ).Length.ShouldBe( 1, "The ring is reused, not recreated." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_secret_key_encrypts_the_key_ring_and_can_be_changed_Async( CancellationToken token )
    {
        const string partyName = "KeyRingSecret";
        Clear( partyName );
        var first = NewSecretKey();
        string current;
        await using( var s = await CreateAsync( partyName, token, c => c["Local:KeyManagement:KeyRingKey"] = first ) )
        {
            current = CurrentKey( s );
        }
        var key = LoadSingleKeyRingFile( partyName );
        GetDecryptorType( key ).ShouldNotBeNull().ShouldContain( nameof( KeyRingStore.SecretKeyXmlDecryptor ) );
        key.Descendants( "masterKey" ).ShouldBeEmpty( "The master key is not in clear." );

        // A new key, the previous one still decrypts the existing ring.
        var second = NewSecretKey();
        await using( var s = await CreateAsync( partyName, token, c =>
        {
            c["Local:KeyManagement:KeyRingKey"] = second;
            c["Local:KeyManagement:KeyRingPreviousKey"] = first;
        } ) )
        {
            CurrentKey( s ).ShouldBe( current );
        }

        // Without the key that encrypted the ring, nothing can be read.
        var decryptor = new KeyRingStore.SecretKeyXmlDecryptor( new ServiceCollection().AddSingleton( ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, c =>
        {
            c["FullName"] = $"Test/${partyName}";
            c["Local:KeyManagement:KeyRingKey"] = second;
        } )! ).BuildServiceProvider() );
        Should.Throw<CryptographicException>( () => decryptor.Decrypt( EncryptedSecrets( key ).Single().Elements().Single() ) );
    }

    [Test]
    public void An_invalid_secret_key_is_an_error()
    {
        var config = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, c =>
        {
            c["FullName"] = "Test/$KeyRingInvalid";
            c["Local:KeyManagement:KeyRingKey"] = "too short";
        } )!;
        var decryptor = new KeyRingStore.SecretKeyXmlDecryptor( new ServiceCollection().AddSingleton( config ).BuildServiceProvider() );
        var e = new XElement( "encryptedKey", new XElement( "secret", new XAttribute( "id", "0000000000000000" ) ), new XElement( "value", "AAAA" ) );
        Should.Throw<InvalidOperationException>( () => decryptor.Decrypt( e ) ).Message.ShouldContain( "KeyManagement:KeyRingKey" );
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_invalid_secret_key_fails_the_start_Async( CancellationToken token )
    {
        const string partyName = "KeyRingInvalidStart";
        Clear( partyName );
        var ex = await Should.ThrowAsync<InvalidOperationException>( async () =>
        {
            await using var s = await CreateAsync( partyName, token, c => c["Local:KeyManagement:KeyRingPreviousKey"] = "not base64!" );
        } );
        ex.Message.ShouldContain( "KeyManagement:KeyRingPreviousKey" );
    }

    [Test]
    public void The_cipher_round_trips_and_detects_tampering()
    {
        var key = RandomNumberGenerator.GetBytes( KeyRingCipher.KeyLength );
        var e = new XElement( "masterKey", new XElement( "value", "secret" ) );
        var sealedValue = KeyRingCipher.Seal( e, key );
        sealedValue.ShouldNotContain( "secret" );
        KeyRingCipher.Open( sealedValue, key ).ToString().ShouldBe( e.ToString() );
        var bytes = Convert.FromBase64String( sealedValue );
        bytes[20] ^= 1;
        Should.Throw<CryptographicException>( () => KeyRingCipher.Open( Convert.ToBase64String( bytes ), key ) );
        Should.Throw<CryptographicException>( () => KeyRingCipher.Open( sealedValue, RandomNumberGenerator.GetBytes( KeyRingCipher.KeyLength ) ) );
    }

    [Test, CancelAfter( 30000 )]
    public async Task A_host_that_persists_the_key_ring_keeps_it_Async( CancellationToken token )
    {
        const string partyName = "KeyRingHost";
        Clear( partyName );
        var hostFolder = TestHelper.TestProjectFolder.Combine( "Obj/KeyRingHost" );
        if( Directory.Exists( hostFolder ) ) Directory.Delete( hostFolder, recursive: true );
        await using( await CreateAsync( partyName, token, dataProtection: b => b.PersistKeysToFileSystem( new DirectoryInfo( hostFolder ) ) ) ) { }
        GetKeyRingFiles( partyName ).ShouldBeEmpty( "Nothing in the store of the party." );
        Directory.GetFiles( hostFolder, "*.xml" ).Length.ShouldBe( 1, "The ring is where the host put it." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task The_cng_store_protects_the_key_ring_Async( CancellationToken token )
    {
        if( !OperatingSystem.IsWindows() ) Assert.Ignore( "CNG is Windows only." );
        const string partyName = "KeyRingCng";
        Clear( partyName );
        Action<MutableConfigurationSection> configure = c => c["Defaults:KeyManagement:CngKeyStore:Provider"] = SoftwareProvider;
        string current;
        ApplicationIdentityService? last = null;
        try
        {
            await using( var s = await CreateAsync( partyName, token, configure, cng: true ) )
            {
                current = CurrentKey( s );
            }
            var key = LoadSingleKeyRingFile( partyName );
            GetDecryptorType( key ).ShouldNotBeNull().ShouldContain( nameof( CngCoreKeyStore.CngKeyRingXmlDecryptor ) );
            var cng = key.Descendants( "cng" ).Single();
            ((string?)cng.Attribute( "provider" )).ShouldBe( SoftwareProvider );
            key.Descendants( "masterKey" ).ShouldBeEmpty( "The master key is not in clear." );

            // A restart reads the ring back through the provider.
            await using( var s = await CreateAsync( partyName, token, configure, cng: true ) )
            {
                CurrentKey( s ).ShouldBe( current, "The identity keys are read back with the key ring protected by the provider." );
                last = s;
            }
        }
        finally
        {
            // The CNG keys live outside the store: the identity keys and the key of the ring.
            if( last != null )
            {
                var store = new CngCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ), null );
                foreach( var n in store.GetKeyNames( TestHelper.Monitor, last ) ) store.DeleteKey( TestHelper.Monitor, last, n );
                var ringKey = CngCoreKeyStore.GetCngName( last, "KeyRing" );
                var provider = new CngProvider( SoftwareProvider );
                if( CngKey.Exists( ringKey, provider ) )
                {
                    using var k = CngKey.Open( ringKey, provider );
                    k.Delete();
                }
            }
        }
    }
}
