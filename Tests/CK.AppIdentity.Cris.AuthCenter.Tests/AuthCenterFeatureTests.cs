using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Monitoring;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

[TestFixture]
public class AuthCenterFeatureTests
{
    // Without local or remote, only the core driver: the designation of the AuthCenters.
    static async Task<ApplicationIdentityService> StartAsync( Action<MutableConfigurationSection> configuration, bool withOidc = false, bool local = false, bool remote = false )
    {
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration ).ShouldNotBeNull();
        var services = new ServiceCollection();
        services.AddSingleton( c );
        services.AddSingleton<ApplicationIdentityService>();
        services.AddSingleton<IDataProtectionProvider>( sp => FakeProtector.Fake );
        services.AddSingleton<DefaultCoreKeyStore>();
        services.AddSingleton<ICoreKeyStore>( sp => sp.GetRequiredService<DefaultCoreKeyStore>() );
        services.AddSingleton<KeyManagementFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<KeyManagementFeatureDriver>() );
        services.AddSingleton<AuthCenterFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<AuthCenterFeatureDriver>() );
        if( local || withOidc )
        {
            services.AddSingleton<LocalAuthCenterFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<LocalAuthCenterFeatureDriver>() );
        }
        if( remote )
        {
            services.AddSingleton<RemoteAuthCenterFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<RemoteAuthCenterFeatureDriver>() );
        }
        if( withOidc )
        {
            services.AddSingleton<IAuthCenterSchemeConfiguration, Oidc.AuthCenterOidcConfiguration>();
            services.AddSingleton<Oidc.AuthCenterOidcFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<Oidc.AuthCenterOidcFeatureDriver>() );
        }
        var s = services.BuildServiceProvider().GetRequiredService<ApplicationIdentityService>();
        _ = ((IHostedService)s).StartAsync( default );
        try
        {
            await s.InitializationTask;
        }
        catch
        {
            await s.DisposeAsync();
            throw;
        }
        return s;
    }

    // The setup runs in the agent loop (its own monitor): the logs are collected from the GrandOutput,
    // that dispatches them asynchronously.
    internal static async Task ShouldLogAsync( GrandOutputMemoryCollector logs, string fragment )
    {
        var all = new List<string>();
        for( int i = 0; i < 50; ++i )
        {
            all.AddRange( logs.ExtractCurrentTexts() );
            if( all.Any( t => t.Contains( fragment ) ) ) return;
            await Task.Delay( 20 );
        }
        Assert.Fail( $"Log containing '{fragment}' not found in:{Environment.NewLine}{string.Join( Environment.NewLine, all )}" );
    }

    static async Task StartMustFailAsync( string expectedError, Action<MutableConfigurationSection> configuration, bool local = false, bool remote = false )
    {
        using var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 );
        await Should.ThrowAsync<Exception>( () => StartAsync( configuration, local: local, remote: remote ) );
        await ShouldLogAsync( logs, expectedError );
    }

    [Test]
    public async Task the_local_party_can_be_its_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Front1";
            c["Parties:1:PartyName"] = "Front2";
            c["Parties:2:PartyName"] = "NoAuth";
            c["Parties:2:DisallowFeatures"] = "AuthCenter";
        } );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        f.IsAvailable.ShouldBeTrue();
        f.Owner.ShouldBeSameAs( s );
        f.AuthCenter.ShouldBeSameAs( s );
        s.Remotes.Single( r => r.PartyName == "$Front1" ).GetFeature<ICrisAuthCenter>().ShouldBeSameAs( f );
        s.Remotes.Single( r => r.PartyName == "$Front2" ).GetFeature<ICrisAuthCenter>().ShouldBeSameAs( f );
        s.Remotes.Single( r => r.PartyName == "$NoAuth" ).GetFeature<ICrisAuthCenter>().ShouldBeNull();
    }

    [Test]
    public async Task the_AuthCenter_verifies_its_tokens_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Front";
        } );
        var keys = s.GetRequiredFeature<ILocalKeys>();
        var f = s.GetRequiredFeature<ICrisAuthCenter>();
        var data = "the-token"u8.ToArray();
        var expiration = DateTime.UtcNow.AddHours( 1 );

        var token = keys.Sign( ICrisAuthCenter.TokenPurpose, data, expiration );
        f.Verify( TestHelper.Monitor, data, token ).ShouldBeTrue();
        // The remotes share the feature: same verification.
        s.Remotes.Single().GetRequiredFeature<ICrisAuthCenter>().Verify( TestHelper.Monitor, data, token ).ShouldBeTrue();

        f.Verify( TestHelper.Monitor, "another-token"u8, token ).ShouldBeFalse( "Tampered data." );
        var other = keys.Sign( "Some.Other.Purpose", data, expiration );
        f.Verify( TestHelper.Monitor, data, other ).ShouldBeFalse( "Another signature of the AuthCenter is not a token." );
    }

    [Test]
    public async Task a_remote_can_be_the_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenter:Session:ExpireTimeSpan"] = "01:00:00";
            c["Parties:1:PartyName"] = "Other";
        } );
        var center = s.Remotes.Single( r => r.PartyName == "$Center" );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        f.AuthCenter.ShouldBeSameAs( center );
        center.GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );
        s.Remotes.Single( r => r.PartyName == "$Other" ).GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );
    }

    [Test]
    public async Task each_local_party_has_its_own_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$SaaS";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
            c["Parties:0:FullName"] = "Acme/$Acme";
            c["Parties:0:Parties:0:PartyName"] = "AcmeCenter";
            c["Parties:0:Parties:0:AuthCenter"] = "true";
            c["Parties:0:Parties:1:PartyName"] = "AcmeBox";
            c["Parties:1:FullName"] = "Opal/$Opal";
            c["Parties:1:Parties:0:PartyName"] = "OpalBox";
        } );
        s.GetFeature<CrisAuthCenter>().ShouldNotBeNull().AuthCenter.ShouldBeSameAs( s );

        var acme = s.TenantDomains.Single( d => d.PartyName == "$Acme" );
        var acmeCenter = acme.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        acmeCenter.AuthCenter.PartyName.ShouldBe( "$AcmeCenter" );
        acme.Remotes.Single( r => r.PartyName == "$AcmeBox" ).GetFeature<CrisAuthCenter>().ShouldBeSameAs( acmeCenter );

        // The "AuthCenter" key is never inherited: Opal (that inherits the allowed feature) has no AuthCenter.
        var opal = s.TenantDomains.Single( d => d.PartyName == "$Opal" );
        opal.GetFeature<CrisAuthCenter>().ShouldBeNull();
        opal.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeNull();
    }

    [Test]
    public async Task no_AuthCenter_is_a_warning_Async()
    {
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            await using var s = await StartAsync( c =>
            {
                c["FullName"] = "D/$App";
                c["AllowFeatures"] = "AuthCenter";
                c["Parties:0:PartyName"] = "Remote";
            } );
            s.GetFeature<CrisAuthCenter>().ShouldBeNull();
            s.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeNull();
            await ShouldLogAsync( logs, "no party is its AuthCenter" );
        }
    }

    [Test]
    public async Task configuration_errors_Async()
    {
        await StartMustFailAsync( "can have only one AuthCenter", c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Remote";
            c["Parties:0:AuthCenter"] = "true";
        } );
        await StartMustFailAsync( "the 'AuthCenter' feature is not allowed", c =>
        {
            c["FullName"] = "D/$App";
            c["AuthCenter"] = "true";
        } );
        await StartMustFailAsync( "the 'AuthCenter' feature is not allowed", c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Remote";
            c["Parties:0:AuthCenter"] = "true";
            c["Parties:0:DisallowFeatures"] = "AuthCenter";
        } );
        await StartMustFailAsync( "it has no 'KeyManagement' feature", c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Remote";
            c["Parties:0:AuthCenter"] = "true";
            c["Parties:0:DisallowFeatures"] = "KeyManagement";
        } );
        await StartMustFailAsync( "expected true, false or a configuration section", c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "yes";
        } );
    }

    [Test]
    public async Task dynamic_parties_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
        } );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();

        // A remote added later receives the feature...
        var r = await s.AddRemoteAsync( TestHelper.Monitor, c => c["PartyName"] = "Late" );
        r.ShouldNotBeNull().GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );

        // ...but cannot be the AuthCenter.
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            (await s.AddRemoteAsync( TestHelper.Monitor, c => { c["PartyName"] = "Usurper"; c["AuthCenter"] = "true"; } )).ShouldBeNull();
            await ShouldLogAsync( logs, "the AuthCenter is defined with its local party" );
        }

        // A tenant domain added later comes with its AuthCenter.
        var acme = await s.AddTenantDomainAsync( TestHelper.Monitor, c =>
        {
            c["FullName"] = "Acme/$Acme";
            c["Parties:0:PartyName"] = "AcmeCenter";
            c["Parties:0:AuthCenter"] = "true";
            c["Parties:1:PartyName"] = "AcmeBox";
        } );
        var acmeCenter = acme.ShouldNotBeNull().GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        acmeCenter.ShouldNotBeSameAs( f );
        var box = acme.Remotes.Single( r => r.PartyName == "$AcmeBox" );
        box.GetFeature<CrisAuthCenter>().ShouldBeSameAs( acmeCenter );

        // When its AuthCenter is destroyed, the tenant domain has no more authentication: the feature fails closed.
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            await ((IRemoteParty)acmeCenter.AuthCenter).DestroyAsync();
            acmeCenter.IsAvailable.ShouldBeFalse();
            acmeCenter.Verify( TestHelper.Monitor, "the-token"u8, default ).ShouldBeFalse();
            box.GetFeature<CrisAuthCenter>().ShouldNotBeNull().IsAvailable.ShouldBeFalse();
            await ShouldLogAsync( logs, "authentication is no more available for 'Acme/$Acme" );
        }
        f.IsAvailable.ShouldBeTrue();
    }

    [Test]
    public async Task an_application_is_the_AuthCenter_or_a_front_not_both_Async()
    {
        // The core alone designates the AuthCenters: here the root is its own one, Acme uses a remote.
        static void Mixed( MutableConfigurationSection c )
        {
            c["FullName"] = "D/$SaaS";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
            c["Parties:0:FullName"] = "Acme/$Acme";
            c["Parties:0:Parties:0:PartyName"] = "AcmeCenter";
            c["Parties:0:Parties:0:AuthCenter"] = "true";
        }
        await using( var s = await StartAsync( Mixed ) )
        {
            s.GetFeature<LocalAuthCenter>().ShouldBeNull();
            s.GetFeature<RemoteAuthCenter>().ShouldBeNull();
        }
        // An AuthCenter application cannot have a remote AuthCenter, a front cannot be its own AuthCenter.
        await StartMustFailAsync( "' but this application is an AuthCenter (CK.AppIdentity.Cris.AuthCenter.Local)", Mixed, local: true );
        await StartMustFailAsync( "is its own AuthCenter but this application is a front of a remote AuthCenter", Mixed, remote: true );

        // Each side adds its feature.
        await using( var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
        }, local: true ) )
        {
            s.GetRequiredFeature<LocalAuthCenter>().Center.ShouldBeSameAs( s.GetRequiredFeature<CrisAuthCenter>() );
        }
        await using( var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenter"] = "true";
        }, remote: true ) )
        {
            s.GetRequiredFeature<RemoteAuthCenter>().Center.AuthCenter.PartyName.ShouldBe( "$Center" );
        }
    }

    static void OidcScheme( MutableConfigurationSection c, string prefix = "" )
    {
        c[$"{prefix}AuthCenter:Oidc:Test:Authority"] = "https://idp.example.com";
        c[$"{prefix}AuthCenter:Oidc:Test:ClientId"] = "client";
        c[$"{prefix}AuthCenter:Oidc:Test:ClientSecret"] = "secret";
        c[$"{prefix}AuthCenter:Oidc:Test:Scopes"] = "openid";
        c[$"{prefix}AuthCenter:Oidc:Test:CallbackUrls:0"] = "https://front.example.com/.auth/oidc/callback";
    }

    [Test]
    public async Task a_scheme_family_section_requires_its_package_Async()
    {
        // Without the Oidc package, its section is an error: a configured family must not silently do nothing.
        await StartMustFailAsync( "AuthCenter:Oidc' section belongs to no installed scheme family (is a package missing?)", c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            OidcScheme( c );
        }, local: true );

        // With the package, the family is a feature of the local party.
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            OidcScheme( c );
        }, withOidc: true );
        var center = s.GetRequiredFeature<LocalAuthCenter>();
        center.SchemeFamilies.ShouldHaveSingleItem().Schemes.ShouldBe( ["Oidc.Test"] );
        center.FindSchemeFamily( "oidc.test" ).ShouldBeOfType<Oidc.AuthCenterOidc>();
    }

    [Test]
    public async Task an_installed_family_without_configuration_has_no_scheme_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            c["AuthCenter"] = "true";
        }, withOidc: true );
        var family = s.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();
        family.ProviderName.ShouldBe( "Oidc" );
        family.Schemes.ShouldBeEmpty( "It still hides the 'Oidc' provider name in the scheme listing." );
    }

    [Test]
    public async Task a_dynamic_tenant_has_its_own_scheme_families_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["AllowFeatures"] = "AuthCenter";
            OidcScheme( c );
        }, withOidc: true );
        var rootFamily = s.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();

        var acme = await s.AddTenantDomainAsync( TestHelper.Monitor, c =>
        {
            c["FullName"] = "Acme/$Acme";
            c["AllowFeatures"] = "AuthCenter";
            OidcScheme( c );
            c["AuthCenter:Oidc:Other:Authority"] = "https://other-idp.example.com";
            c["AuthCenter:Oidc:Other:ClientId"] = "client";
            c["AuthCenter:Oidc:Other:ClientSecret"] = "secret";
            c["AuthCenter:Oidc:Other:Scopes"] = "openid";
            c["AuthCenter:Oidc:Other:CallbackUrls:0"] = "https://acme.example.com/.auth/oidc/callback";
        } );
        var acmeFamily = acme.ShouldNotBeNull().GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();
        acmeFamily.ShouldNotBeSameAs( rootFamily );
        acmeFamily.Schemes.ShouldBe( ["Oidc.Test", "Oidc.Other"], ignoreOrder: true );
    }
}
