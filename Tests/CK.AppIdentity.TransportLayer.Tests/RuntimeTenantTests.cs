using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The run-time tenant domains (the instances of an Opened tenant template) with the key management and the transport:
/// a removed tenant has its keys destroyed (never trashed), a new tenant listens as a configured one does.
/// </summary>
[TestFixture]
public class RuntimeTenantTests
{
    const string SoftwareProvider = "Microsoft Software Key Storage Provider";

    // An Opened tenant template "Test/{prefix}/{Name}" of the root party.
    static Action<MutableConfigurationSection> WithTenants( string prefix, Action<MutableConfigurationSection>? more = null )
        => c =>
        {
            c["Parties:0:DomainName"] = $"Test/{prefix}/{{Name}}";
            c["Parties:0:PartyName"] = "${Name}";
            c["Parties:0:InstanceCount"] = "0";
            c["Parties:0:MaxInstanceCount"] = "2";
            more?.Invoke( c );
        };

    static void Clear( string prefix )
    {
        var f = ApplicationIdentityServiceConfiguration.DefaultStoreRootPath.Combine( $"#Dev/Test/{prefix}" );
        if( Directory.Exists( f ) ) Directory.Delete( f, recursive: true );
    }

    static string[] Files( NormalizedPath folder, string pattern = "*" )
    {
        return Directory.Exists( folder )
                ? Directory.EnumerateFiles( folder, pattern, SearchOption.AllDirectories ).Select( f => Path.GetFileName( f ) ).ToArray()
                : [];
    }

    [Test, CancelAfter( 30000 )]
    public async Task a_removed_runtime_tenant_has_its_keys_destroyed_Async( CancellationToken token )
    {
        const string prefix = "RTKeys";
        Clear( prefix );
        IdentityStoreHelper.ClearKeys( "RTKeysHolder" );
        await using var s = await IdentityStoreHelper.CreateAsync( "RTKeysHolder", new HeaderProtector(), token, configure: WithTenants( prefix ) );
        var acme = (await s.AddTenantInstanceAsync( TestHelper.Monitor, s.TenantTemplates[0], "Acme" )).ShouldNotBeNull();
        var local = acme.LocalFileStore.FolderPath;
        acme.GetRequiredFeature<ILocalKeys>().ShouldNotBeNull( "The tenant has its own identity." );
        Files( local.AppendPart( DefaultCoreKeyStore.FolderName ), "*.key" ).ShouldNotBeEmpty();

        (await s.RemoveTenantInstanceAsync( TestHelper.Monitor, acme.FullName )).ShouldBeTrue();

        Files( local.AppendPart( DefaultCoreKeyStore.FolderName ), "*.key" ).ShouldBeEmpty( "The identity keys are destroyed." );
        Files( local.Combine( "KeyManagement/EncryptionKeys" ) ).ShouldBeEmpty( "The encryption keys are destroyed." );
        File.Exists( local.AppendPart( "Instance.json" ) ).ShouldBeFalse();
        // What remains (the key event log, the certificate, the record) is in the trash bin: no key is there.
        var trashed = Directory.EnumerateFiles( local.AppendPart( "$TrashBin" ) ).Where( f => f.EndsWith( ".binInfo" ) ).Select( File.ReadAllText ).ToArray();
        trashed.ShouldContain( "Instance.json" );
        trashed.ShouldNotContain( p => p.EndsWith( ".key" ) );
    }

    [Test, CancelAfter( 30000 )]
    public async Task a_removed_runtime_tenant_has_its_cng_keys_destroyed_Async( CancellationToken token )
    {
        if( !OperatingSystem.IsWindows() ) Assert.Ignore( "CNG is Windows only." );
        const string prefix = "RTCng";
        Clear( prefix );
        IdentityStoreHelper.ClearKeys( "RTCngHolder" );
        await using var s = await IdentityStoreHelper.CreateAsync( "RTCngHolder",
                                                                    new HeaderProtector(),
                                                                    token,
                                                                    configure: WithTenants( prefix, c => c["Defaults:KeyManagement:CngKeyStore:Provider"] = SoftwareProvider ),
                                                                    keyStore: sp => new CngCoreKeyStore( sp.GetRequiredService<DefaultCoreKeyStore>(), sp ),
                                                                    options: [typeof( CngKeyStoreOption )] );
        var acme = (await s.AddTenantInstanceAsync( TestHelper.Monitor, s.TenantTemplates[0], "Acme" )).ShouldNotBeNull();
        var coreKeys = acme.LocalFileStore.FolderPath.AppendPart( DefaultCoreKeyStore.FolderName );
        var cngNames = Directory.EnumerateFiles( coreKeys, "*.cng" ).Select( f => File.ReadAllText( f ).Split( '\n' )[2] ).ToArray();
        cngNames.ShouldNotBeEmpty( "The keys of the tenant are in the provider." );
        var provider = new CngProvider( SoftwareProvider );
        cngNames.ShouldAllBe( n => CngKey.Exists( n, provider, CngKeyOpenOptions.None ) );

        (await s.RemoveTenantInstanceAsync( TestHelper.Monitor, acme.FullName )).ShouldBeTrue();

        cngNames.ShouldAllBe( n => !CngKey.Exists( n, provider, CngKeyOpenOptions.None ), "The keys are destroyed in the provider: none is orphaned." );
        Files( coreKeys, "*.cng" ).ShouldBeEmpty( "The markers are deleted." );
    }

    [Test, CancelAfter( 30000 )]
    public async Task a_runtime_tenant_with_an_Opened_template_of_listening_remotes_listens_Async( CancellationToken token )
    {
        const string prefix = "RTListen";
        Clear( prefix );
        IdentityStoreHelper.ClearKeys( "RTListenHolder" );
        await using var s = await IdentityStoreHelper.CreateAsync( "RTListenHolder", new HeaderProtector(), token, configure: WithTenants( prefix, c =>
        {
            // The candidates of this template call before any of its remotes exists: the tenant listens.
            c["Parties:0:Parties:0:PartyName"] = "$Worker-{Name}";
            c["Parties:0:Parties:0:InstanceCount"] = "0";
            c["Parties:0:Parties:0:MaxInstanceCount"] = "2";
            c["Parties:0:Parties:0:KeyManagement:AutoTrustKey"] = "Never";
        } ) );
        var acme = (await s.AddTenantInstanceAsync( TestHelper.Monitor, s.TenantTemplates[0], "Acme" )).ShouldNotBeNull();
        acme.RemoteTemplates.ShouldHaveSingleItem();
        acme.GetFeature<TransportListener[]>().ShouldNotBeNull( "A run-time tenant listens as a configured one does." );
        (await s.RemoveTenantInstanceAsync( TestHelper.Monitor, acme.FullName )).ShouldBeTrue();
    }
}
