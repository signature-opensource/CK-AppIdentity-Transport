using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
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
/// <see cref="CngCoreKeyStore"/>, driven on the CNG SOFTWARE key storage provider: the very code path the
/// TPM takes (named persisted keys, not exportable, opened and deleted by name), without the hardware.
/// The provider is chosen the way a deployment chooses it: by configuration. One test uses the real TPM
/// provider and is skipped while no TPM is usable.
/// </summary>
[TestFixture]
public class CngCoreKeyStoreTests
{
    const string SoftwareProvider = "Microsoft Software Key Storage Provider";
    const string NoProvider = "No Such Provider";

    static Func<IServiceProvider, ICoreKeyStore> Cng() => sp => new CngCoreKeyStore( sp.GetRequiredService<DefaultCoreKeyStore>() );

    static Action<MutableConfigurationSection> Configure( string? provider, bool? allowFallback = null, bool? machineWide = null )
        => c =>
        {
            if( provider != null ) c["CoreKeyStore:CngProvider"] = provider;
            if( allowFallback.HasValue ) c["CoreKeyStore:AllowFallback"] = allowFallback.Value ? "true" : "false";
            if( machineWide.HasValue ) c["CoreKeyStore:MachineWide"] = machineWide.Value ? "true" : "false";
        };

    static string[] Files( string partyName, string pattern )
    {
        var folder = IdentityStoreHelper.GetCoreKeysFolder( partyName );
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, pattern ).Select( f => Path.GetFileName( f ) ).OrderBy( n => n ).ToArray()
                : Array.Empty<string>();
    }

    /// <summary>
    /// Destroys the keys a test left in a provider: CNG keys live outside the test store, and clearing the
    /// store's folders would orphan them.
    /// </summary>
    static void DestroyKeys( ApplicationIdentityService s )
    {
        var store = new CngCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ) );
        foreach( var n in store.GetKeyNames( TestHelper.Monitor, s ) ) store.DeleteKey( TestHelper.Monitor, s, n );
    }

    static void RequireWindows()
    {
        if( !OperatingSystem.IsWindows() ) Assert.Ignore( "CNG is Windows only." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Keys_live_in_the_provider_not_in_files_Async( CancellationToken token )
    {
        RequireWindows();
        const string partyName = "CngSoft";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] spki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, configure: Configure( SoftwareProvider ), keyStore: Cng() ) )
        {
            spki = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.ToArray();
            Files( partyName, "*.key" ).ShouldBeEmpty( "No key is in a file." );
            Files( partyName, "*.cng" ).ShouldBe( new[] { "0.cng", "1.cng", "recovery-0.cng" }, "Only the markers that say where the keys are." );
            File.ReadAllText( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "0.cng" ) ).ShouldStartWith( SoftwareProvider + "\nuser\n" );

            // The private key cannot be taken out of the provider, but it signs.
            using var key = new CngCoreKeyStore( new DefaultCoreKeyStore( protector ) ).OpenKey( TestHelper.Monitor, s, "0" ).ShouldNotBeNull();
            Should.Throw<CryptographicException>( () => key.ExportPkcs8PrivateKey() );
            var hash = SHA256.HashData( "data"u8 );
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo( spki, out _ );
            verifier.VerifyHash( hash, key.SignHash( hash ) ).ShouldBeTrue();
        }

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, configure: Configure( SoftwareProvider ), keyStore: Cng() ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki, "A restart reopens the very same keys by name." );

            // Rotation destroys the superseded key in the provider, not only its marker.
            var cngName = CngCoreKeyStore.GetCngName( s, "0" );
            CngKey.Exists( cngName, new CngProvider( SoftwareProvider ) ).ShouldBeTrue();
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
            CngKey.Exists( cngName, new CngProvider( SoftwareProvider ) ).ShouldBeFalse( "Destroyed, not merely forgotten." );
            Files( partyName, "*.cng" ).ShouldBe( new[] { "1.cng", "2.cng", "recovery-0.cng" } );
            DestroyKeys( s );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task An_unusable_provider_refuses_the_start_unless_fallback_is_allowed_Async( CancellationToken token )
    {
        const string partyName = "CngNone";
        IdentityStoreHelper.ClearKeys( partyName );
        new CngCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ) ).IsUsable( NoProvider, out var reason ).ShouldBeFalse();
        reason.ShouldNotBeNull();

        // Required by default: no silent downgrade to file keys.
        await Should.ThrowAsync<CKException>( () => IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                                    configure: Configure( NoProvider ), keyStore: Cng() ) );
        Files( partyName, "*.key" ).ShouldBeEmpty( "Nothing was created." );

        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                    configure: Configure( NoProvider, allowFallback: true ), keyStore: Cng() ) )
        {
            s.GetRequiredFeature<ILocalKeys>().Seq.ShouldBe( 0 );
        }
        Files( partyName, "*.key" ).ShouldBe( new[] { "0.key", "1.key", "recovery-0.key" } );
        Files( partyName, "*.cng" ).ShouldBeEmpty();

        // Those file keys exist now: they still must not be used once fallback is no more allowed.
        await Should.ThrowAsync<CKException>( () => IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                                                    configure: Configure( NoProvider ), keyStore: Cng() ) );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Keys_remember_their_provider_across_configuration_changes_Async( CancellationToken token )
    {
        // Keys of the default store stay readable when a provider appears, and keys of a provider stay
        // readable when the configuration names another: each key is opened where its marker says.
        RequireWindows();
        const string partyName = "CngMoves";
        IdentityStoreHelper.ClearKeys( partyName );
        var protector = new HeaderProtector();
        byte[] spki;
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token ) )
        {
            spki = s.GetRequiredFeature<ILocalKeys>().CurrentIdentity.PublicKeyRawData.ToArray();
        }
        Files( partyName, "*.key" ).Length.ShouldBe( 3, "Created by the default store." );

        // The provider appears: the identity is unchanged, new keys go to it.
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, configure: Configure( SoftwareProvider ), keyStore: Cng() ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki, "The key of the default store is found." );
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue();
            Files( partyName, "*.cng" ).ShouldBe( new[] { "2.cng" } );
            Files( partyName, "*.key" ).ShouldBe( new[] { "1.key", "recovery-0.key" } );
            spki = keys.CurrentIdentity.PublicKeyRawData.ToArray();
        }

        // The configuration now names a provider that is not usable, with fallback: the keys of the
        // software provider are still opened there, and the next ones go to files.
        await using( var s = await IdentityStoreHelper.CreateAsync( partyName, protector, token, configure: Configure( NoProvider, allowFallback: true ), keyStore: Cng() ) )
        {
            var keys = s.GetRequiredFeature<ILocalKeys>();
            keys.CurrentIdentity.PublicKeyRawData.ToArray().ShouldBe( spki );
            // This rotation reveals key 2 and is signed by it: it is opened in the provider its marker names.
            keys.Rotate( TestHelper.Monitor ).ShouldBeTrue( "Key 2 is opened in the software provider." );
            Files( partyName, "*.cng" ).ShouldBe( new[] { "2.cng" } );
            Files( partyName, "*.key" ).ShouldBe( new[] { "3.key", "recovery-0.key" } );
            keys.Recover( TestHelper.Monitor ).ShouldBeTrue( "A recovery with the stored recovery key works across both." );
            Files( partyName, "*.cng" ).ShouldBeEmpty( "The superseded provider key is destroyed in its provider." );
            CngKey.Exists( CngCoreKeyStore.GetCngName( s, "2" ), new CngProvider( SoftwareProvider ) ).ShouldBeFalse();
            DestroyKeys( s );
        }
    }

    [Test, CancelAfter( 30000 )]
    public async Task Decommissioning_destroys_the_keys_in_the_provider_Async( CancellationToken token )
    {
        // Decommissioning deletes every key the store lists: provider keys must be listed too.
        RequireWindows();
        const string partyName = "CngEnd";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, configure: Configure( SoftwareProvider ), keyStore: Cng() );
        var names = new[] { "0", "1", "recovery-0" }.Select( n => CngCoreKeyStore.GetCngName( s, n ) ).ToArray();
        names.ShouldAllBe( n => CngKey.Exists( n, new CngProvider( SoftwareProvider ) ) );
        s.GetRequiredFeature<ILocalKeys>().Decommission( TestHelper.Monitor ).ShouldBeTrue();
        names.ShouldAllBe( n => !CngKey.Exists( n, new CngProvider( SoftwareProvider ) ), "Destroyed in the provider." );
        Files( partyName, "*.cng" ).ShouldBeEmpty();
    }

    [Test, CancelAfter( 30000 )]
    public async Task Configuration_is_inherited_from_the_root_Async( CancellationToken token )
    {
        // Set once at the root, it applies to the party: the lookup walks up the sections.
        RequireWindows();
        const string partyName = "CngRoot";
        IdentityStoreHelper.ClearKeys( partyName );
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                    configure: c => c["CoreKeyStore:CngProvider"] = SoftwareProvider, keyStore: Cng() );
        Files( partyName, "*.cng" ).Length.ShouldBe( 3 );
        DestroyKeys( s );
    }

    [Test, CancelAfter( 30000 )]
    public async Task Machine_wide_keys_are_recorded_as_such_Async( CancellationToken token )
    {
        RequireWindows();
        const string partyName = "CngMachine";
        IdentityStoreHelper.ClearKeys( partyName );
        ApplicationIdentityService? s = null;
        try
        {
            s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token,
                                                        configure: Configure( SoftwareProvider, machineWide: true ), keyStore: Cng() );
        }
        catch( CKException ex )
        {
            Assert.Ignore( $"Machine keys cannot be created by this account here: {ex.Message}" );
        }
        await using( s )
        {
            File.ReadAllText( IdentityStoreHelper.GetCoreKeysFolder( partyName ).AppendPart( "0.cng" ) ).ShouldStartWith( SoftwareProvider + "\nmachine\n" );
            CngKey.Exists( CngCoreKeyStore.GetCngName( s, "0" ), new CngProvider( SoftwareProvider ), CngKeyOpenOptions.MachineKey ).ShouldBeTrue();
            CngKey.Exists( CngCoreKeyStore.GetCngName( s, "0" ), new CngProvider( SoftwareProvider ), CngKeyOpenOptions.None ).ShouldBeFalse(
                "Not a key of the user." );
            s.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue();
            DestroyKeys( s );
        }
    }

    [Test, CancelAfter( 60000 )]
    public async Task On_a_real_TPM_the_identity_keys_are_in_the_chip_Async( CancellationToken token )
    {
        var probe = new CngCoreKeyStore( new DefaultCoreKeyStore( new HeaderProtector() ) );
        if( !probe.IsUsable( CngCoreKeyStore.DefaultProviderName, out var reason ) ) Assert.Ignore( $"No usable TPM on this machine: {reason}" );

        const string partyName = "CngTpm";
        IdentityStoreHelper.ClearKeys( partyName );
        // No configuration: the TPM is the default provider.
        await using var s = await IdentityStoreHelper.CreateAsync( partyName, new HeaderProtector(), token, keyStore: Cng() );
        Files( partyName, "*.key" ).ShouldBeEmpty();
        s.GetRequiredFeature<ILocalKeys>().Rotate( TestHelper.Monitor ).ShouldBeTrue( "The chip signs the event and the certificate." );
        DestroyKeys( s );
    }
}
