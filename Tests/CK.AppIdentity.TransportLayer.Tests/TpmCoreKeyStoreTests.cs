using CK.AppIdentity.KeyManagement;
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
/// <see cref="TpmCoreKeyStore"/>, driven on the CNG SOFTWARE key storage provider: the very code path the
/// TPM takes (named persisted keys, non-exportable, opened and deleted by name), without the hardware.
/// One test uses the real TPM provider and is skipped while no TPM is usable.
/// </summary>
[TestFixture]
public class TpmCoreKeyStoreTests
{
    const string SoftwareProvider = "Microsoft Software Key Storage Provider";

    static Func<IServiceProvider, ICoreKeyStore> On( string provider )
        => sp => new TpmCoreKeyStore( sp.GetRequiredService<DefaultCoreKeyStore>(), provider );

    static string[] Files( string partyName, string pattern )
    {
        var folder = IdentityStoreHelper.GetCoreKeysFolder( partyName );
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, pattern ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    /// <summary>
    /// Destroys the keys a test left in the provider: CNG keys live in the user profile, not in the
    /// test store, and clearing the store's folders would orphan them.
    /// </summary>
    static void DestroyKeys( ICoreKeyStore store, ILocalParty party )
    {
        foreach( var n in store.GetKeyNames( TestHelper.Monitor, party ) ) store.DeleteKey( TestHelper.Monitor, party, n );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Keys_live_in_the_provider_not_in_files_Async( CancellationToken token )
    {
        if( !OperatingSystem.IsWindows() ) Assert.Ignore( "CNG is Windows only." );
        const string partyName = "TpmSoft";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] spki;
        var store = new TpmCoreKeyStore( new DefaultCoreKeyStore( protector ), SoftwareProvider );
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, keyStore: _ => store ) )
        {
            store.IsAvailable.ShouldBeTrue( store.UnavailableReason );
            spki = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.ToArray();

            Files( partyName, "*.key" ).ShouldBeEmpty( "No key is in a file." );
            Files( partyName, "*.tpm" ).ShouldBe( new[] { "0.tpm", "1.tpm", "recovery-0.tpm" }, "Only the markers that say where the keys are." );

            // The private key cannot be taken out of the provider.
            using var key = store.OpenKey( TestHelper.Monitor, s, "0" ).ShouldNotBeNull();
            Should.Throw<CryptographicException>( () => key.ExportPkcs8PrivateKey() );
            // But it signs.
            var hash = SHA256.HashData( "data"u8 );
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo( spki, out _ );
            verifier.VerifyHash( hash, key.SignHash( hash ) ).ShouldBeTrue();
        }

        // A restart reopens the very same keys by name.
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, keyStore: On( SoftwareProvider ) ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki );

            // Rotation destroys the superseded key in the provider, not only its marker.
            var cngName = TpmCoreKeyStore.GetCngName( s, "0" );
            CngKey.Exists( cngName, new CngProvider( SoftwareProvider ) ).ShouldBeTrue();
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
            CngKey.Exists( cngName, new CngProvider( SoftwareProvider ) ).ShouldBeFalse( "Destroyed, not merely forgotten." );
            Files( partyName, "*.tpm" ).ShouldBe( new[] { "1.tpm", "2.tpm", "recovery-0.tpm" } );

            DestroyKeys( new TpmCoreKeyStore( new DefaultCoreKeyStore( protector ), SoftwareProvider ), s );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task Without_a_usable_provider_keys_go_to_the_default_store_Async( CancellationToken token )
    {
        const string partyName = "TpmNone";
        IdentityStoreHelper.ClearKeys( partyName );
        var store = new TpmCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ), "No Such Provider" );
        store.IsAvailable.ShouldBeFalse();
        store.UnavailableReason.ShouldNotBeNull();

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, keyStore: On( "No Such Provider" ) ) )
        {
            s.GetRequiredFeature<ILocalKeys>().Seq.ShouldBe( 0 );
        }
        Files( partyName, "*.key" ).ShouldBe( new[] { "0.key", "1.key", "recovery-0.key" } );
        Files( partyName, "*.tpm" ).ShouldBeEmpty();
    }

    [Test, CancelAfter( 30000 )]
    public async Task Keys_of_the_default_store_stay_readable_when_the_provider_appears_Async( CancellationToken token )
    {
        // A machine whose TPM gets enabled after the identity was created: nothing is lost, and the keys
        // created from then on go to the provider.
        if( !OperatingSystem.IsWindows() ) Assert.Ignore( "CNG is Windows only." );
        const string partyName = "TpmLater";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] spki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            spki = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.ToArray();
        }
        Files( partyName, "*.key" ).Length.ShouldBe( 3 );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, keyStore: On( SoftwareProvider ) ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki, "The key of the default store is found." );
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
            Files( partyName, "*.tpm" ).ShouldBe( new[] { "2.tpm" }, "The new key is created in the provider." );
            Files( partyName, "*.key" ).ShouldBe( new[] { "1.key", "recovery-0.key" }, "The superseded file key is gone." );

            // And a recovery, with the recovery key of the default store, works across both.
            keys.Recover( TestHelper.Monitor ).ShouldBeTrue();
            Files( partyName, "*.key" ).ShouldBeEmpty();

            DestroyKeys( new TpmCoreKeyStore( new DefaultCoreKeyStore( protector ), SoftwareProvider ), s );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task On_a_real_TPM_the_identity_keys_are_in_the_chip_Async( CancellationToken token )
    {
        var probe = new TpmCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ) );
        if( !probe.IsAvailable ) Assert.Ignore( $"No usable TPM on this machine: {probe.UnavailableReason}" );

        const string partyName = "TpmReal";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token,
                                    keyStore: sp => new TpmCoreKeyStore( sp.GetRequiredService<DefaultCoreKeyStore>() ) );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        Files( partyName, "*.key" ).ShouldBeEmpty();
        keys.Rotate( TestHelper.Monitor ).ShouldBeTrue( "The chip signs the event and the certificate." );
        DestroyKeys( probe, s );
    }
}
