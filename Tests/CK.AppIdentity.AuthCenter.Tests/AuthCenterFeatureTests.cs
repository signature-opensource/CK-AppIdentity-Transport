using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Testing;
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

namespace CK.AppIdentity.AuthCenter.Tests;

[TestFixture]
public class AuthCenterFeatureTests
{
    // The installed sides: local (a local party can be the AuthCenter), remote (a local party can use a remote AuthCenter).
    static async Task<ApplicationIdentityService> StartAsync( Action<MutableConfigurationSection> configuration,
                                                              bool withOidc = false,
                                                              bool local = false,
                                                              bool remote = false,
                                                              ILoginProvider? loginProvider = null )
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
        if( local || withOidc )
        {
            services.AddSingleton<LocalAuthCenterFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<LocalAuthCenterFeatureDriver>() );
        }
        // The Local side requires the Remote side: in an application, its package brings it (the scope of a party is
        // checked at start).
        if( remote || local || withOidc )
        {
            services.AddSingleton<RemoteAuthCenterFeatureDriver>();
            services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<RemoteAuthCenterFeatureDriver>() );
        }
        if( withOidc )
        {
            // The OpenID Connect scheme family is an option of the AuthCenter.
            services.AddSingleton<Oidc.AuthCenterOidcHttpClient>();
            services.AddPartyComponentOptions( typeof( Oidc.AuthCenterOidcOption ) );
            if( loginProvider != null ) services.AddSingleton( loginProvider );
        }
        // The Local side requires the Remote side: it is in the directory.
        services.AddPartyComponentDirectory( typeof( RemoteAuthCenterFeatureDriver ) );
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
    public async Task the_local_party_that_allows_the_feature_is_its_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Local:AuthCenter"] = "true";
            c["Defaults:AuthCenterRemote"] = "true";
            c["Parties:0:PartyName"] = "Front1";
            c["Parties:1:PartyName"] = "Front2";
            c["Parties:2:PartyName"] = "NoAuth";
            c["Parties:2:AuthCenterRemote"] = "false";
        }, local: true );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        f.IsAvailable.ShouldBeTrue();
        f.Owner.ShouldBeSameAs( s );
        f.AuthCenter.ShouldBeSameAs( s );
        // Its remotes that allow "AuthCenterRemote" share it.
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
            c["Local:AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Front";
            c["Parties:0:AuthCenterRemote"] = "true";
        }, local: true );
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
    public async Task the_remote_that_allows_AuthCenterRemote_is_the_AuthCenter_of_a_local_party_that_is_not_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenterRemote"] = "true";
            c["Parties:1:PartyName"] = "Other";
        }, remote: true );
        var center = s.Remotes.Single( r => r.PartyName == "$Center" );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        f.AuthCenter.ShouldBeSameAs( center );
        center.GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );
        s.Remotes.Single( r => r.PartyName == "$Other" ).GetFeature<CrisAuthCenter>().ShouldBeNull();
        s.GetRequiredFeature<RemoteAuthCenter>().Center.ShouldBeSameAs( f );
    }

    [Test]
    public async Task each_local_party_that_allows_the_feature_is_its_own_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$SaaS";
            c["Defaults:AuthCenter"] = "true";
            c["Defaults:AuthCenterRemote"] = "true";
            c["Parties:0:FullName"] = "Acme/$Acme";
            c["Parties:0:Parties:0:PartyName"] = "AcmeBox";
            c["Parties:1:FullName"] = "Opal/$Opal";
            c["Parties:1:Defaults:AuthCenter"] = "false";
            c["Parties:1:Defaults:AuthCenterRemote"] = "false";
            c["Parties:1:Parties:0:PartyName"] = "OpalBox";
        }, local: true );
        s.GetFeature<CrisAuthCenter>().ShouldNotBeNull().AuthCenter.ShouldBeSameAs( s );

        var acme = s.TenantDomains.Single( d => d.PartyName == "$Acme" );
        var acmeCenter = acme.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        acmeCenter.AuthCenter.ShouldBeSameAs( acme );
        acme.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeSameAs( acmeCenter );

        // Opal's "Defaults" disallow both names for its local party and its remotes: no AuthCenter.
        var opal = s.TenantDomains.Single( d => d.PartyName == "$Opal" );
        opal.GetFeature<CrisAuthCenter>().ShouldBeNull();
        opal.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeNull();
    }

    [Test]
    public async Task without_AuthCenter_nor_AuthCenterRemote_there_is_no_authentication_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Remote";
        }, local: true, remote: true );
        s.GetFeature<CrisAuthCenter>().ShouldBeNull();
        s.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeNull();
    }

    [Test]
    public async Task without_its_side_package_the_feature_is_ignored_Async()
    {
        // Only the Remote side: the local party that allows "AuthCenter" cannot be it.
        await using( var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Local:AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Front";
            c["Parties:0:AuthCenterRemote"] = "true";
        }, remote: true ) )
        {
            s.GetFeature<CrisAuthCenter>().ShouldBeNull();
        }
        // "Only the Local side" doesn't exist: the Local side requires the Remote side (its package brings it, the scope
        // of a party is checked at start).
    }

    [Test]
    public async Task configuration_errors_Async()
    {
        await StartMustFailAsync( "it can use only one remote that is the 'AuthCenter'", c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Remote1";
            c["Parties:0:AuthCenterRemote"] = "true";
            c["Parties:1:PartyName"] = "Remote2";
            c["Parties:1:AuthCenterRemote"] = "true";
        }, remote: true );
        await StartMustFailAsync( "declares the feature: true, false or the settings of a local AuthCenter", c =>
        {
            c["FullName"] = "D/$App";
            c["Local:AuthCenter"] = "Center";
        }, local: true );
        await StartMustFailAsync( "an AuthCenter is not designated", c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenterRemote"] = "true";
            c["Parties:0:AuthCenter:Session:ExpireTimeSpan"] = "01:00:00";
        }, remote: true );
        await StartMustFailAsync( "it has no 'KeyManagement' feature", c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenterRemote"] = "true";
            c["Parties:0:KeyManagement"] = "false";
        }, remote: true );
        // A remote that declares "AuthCenter" (the key of a local party that is the feature) is an error.
        await StartMustFailAsync( "'D/$Center/#Dev' declares the 'AuthCenter' feature: 'AuthCenter' is declared in the \"Local\" of a local party that is the feature.", c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenter"] = "true";
        }, local: true, remote: true );
        await StartMustFailAsync( "0 when the scheme never elevates to the Critical level", c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            c["Local:AuthCenter:CriticalLifetimes:Basic"] = "-00:01:00";
        }, local: true );
        await StartMustFailAsync( "cannot exceed the SessionLifetime", c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            c["Local:AuthCenter:SessionLifetime"] = "01:00:00";
            c["Local:AuthCenter:CriticalLifetimes:Basic"] = "02:00:00";
        }, local: true );
    }

    [Test]
    public async Task dynamic_parties_of_an_AuthCenter_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            c["Defaults:AuthCenterRemote"] = "true";
            c["Parties:0:FullName"] = "Acme/$Acme";
            c["Parties:0:Parties:0:PartyName"] = "AcmeBox";
        }, local: true );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();

        // A remote added later receives the feature (the root's "Defaults" declare "AuthCenterRemote").
        var r = await s.AddRemoteAsync( TestHelper.Monitor, c => c["PartyName"] = "Late" );
        r.ShouldNotBeNull().GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );

        // The former designation is an error.
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            (await s.AddRemoteAsync( TestHelper.Monitor, c => { c["PartyName"] = "Usurper"; c["AuthCenter"] = "true"; } )).ShouldBeNull();
            await ShouldLogAsync( logs, "an AuthCenter is not designated" );
        }

        // A tenant domain is its own AuthCenter (the root's "Defaults" declare "AuthCenter" and "AuthCenterRemote").
        var acme = s.TenantDomains.Single();
        var acmeCenter = acme.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        acmeCenter.ShouldNotBeSameAs( f );
        acmeCenter.AuthCenter.ShouldBeSameAs( acme );
        acme.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeSameAs( acmeCenter );

        // A remote added later to the tenant domain receives its AuthCenter.
        var late = await acme.AddRemoteAsync( TestHelper.Monitor, c => c["PartyName"] = "AcmeLate" );
        late.ShouldNotBeNull().GetFeature<CrisAuthCenter>().ShouldBeSameAs( acmeCenter );
    }

    [Test]
    public async Task dynamic_parties_of_a_remote_application_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenterRemote"] = "true";
            c["Parties:1:FullName"] = "Acme/$Acme";
        }, remote: true );
        var f = s.GetFeature<CrisAuthCenter>().ShouldNotBeNull();

        // A remote added later cannot be a second AuthCenter.
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            (await s.AddRemoteAsync( TestHelper.Monitor, c => { c["PartyName"] = "Usurper"; c["AuthCenterRemote"] = "true"; } )).ShouldBeNull();
            await ShouldLogAsync( logs, "already uses the AuthCenter 'D/$Center/#Dev': a local party can use only one remote AuthCenter." );
        }

        // A tenant domain gets its AuthCenter when a remote of its own is added later (the one of the root is not its).
        var acme = s.TenantDomains.Single();
        acme.GetFeature<CrisAuthCenter>().ShouldBeNull();
        var center = await acme.AddRemoteAsync( TestHelper.Monitor, c =>
        {
            c["PartyName"] = "AcmeCenter";
            c["AuthCenterRemote"] = "true";
        } );
        center.ShouldNotBeNull();
        var acmeCenter = acme.GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        acmeCenter.AuthCenter.ShouldBeSameAs( center );

        // When its AuthCenter is destroyed, the tenant domain has no more authentication: the feature fails closed.
        using( var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 ) )
        {
            await ((IRemoteParty)acmeCenter.AuthCenter).DestroyAsync();
            acmeCenter.IsAvailable.ShouldBeFalse();
            acmeCenter.Verify( TestHelper.Monitor, "the-token"u8, default ).ShouldBeFalse();
            await ShouldLogAsync( logs, "authentication is no more available for 'Acme/$Acme" );
        }
        f.IsAvailable.ShouldBeTrue();
    }

    [Test]
    public async Task a_remote_added_later_can_be_the_AuthCenter_Async()
    {
        await using var s = await StartAsync( c => c["FullName"] = "D/$Front", remote: true );
        s.GetFeature<CrisAuthCenter>().ShouldBeNull();
        var r = await s.AddRemoteAsync( TestHelper.Monitor, c => { c["PartyName"] = "Late"; c["AuthCenterRemote"] = "true"; } );
        var f = r.ShouldNotBeNull().GetFeature<CrisAuthCenter>().ShouldNotBeNull();
        f.AuthCenter.ShouldBeSameAs( r );
        s.GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );
        s.GetRequiredFeature<RemoteAuthCenter>().Center.ShouldBeSameAs( f );
    }

    [Test]
    public async Task the_role_of_a_local_party_is_its_configuration_and_both_sides_coexist_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            // The root is the AuthCenter: its Peer uses it.
            c["Local:AuthCenter"] = "true";
            c["Parties:0:PartyName"] = "Peer";
            c["Parties:0:AuthCenterRemote"] = "true";
            // The Acme tenant uses a remote AuthCenter.
            c["Parties:1:FullName"] = "Acme/$Acme";
            c["Parties:1:Parties:0:PartyName"] = "AcmeCenter";
            c["Parties:1:Parties:0:AuthCenterRemote"] = "true";
        }, local: true, remote: true );
        var f = s.GetRequiredFeature<CrisAuthCenter>();
        f.AuthCenter.ShouldBeSameAs( s );
        s.GetRequiredFeature<LocalAuthCenter>().Center.ShouldBeSameAs( f );
        s.GetFeature<RemoteAuthCenter>().ShouldBeNull();
        s.Remotes.Single().GetFeature<CrisAuthCenter>().ShouldBeSameAs( f );

        var acme = s.TenantDomains.Single();
        acme.GetRequiredFeature<RemoteAuthCenter>().Center.AuthCenter.PartyName.ShouldBe( "$AcmeCenter" );
        acme.GetFeature<LocalAuthCenter>().ShouldBeNull();
    }

    static void OidcScheme( MutableConfigurationSection c, string prefix = "Local:" )
    {
        c[$"{prefix}AuthCenter:Oidc:Test:Authority"] = "https://idp.example.com";
        c[$"{prefix}AuthCenter:Oidc:Test:ClientId"] = "client";
        c[$"{prefix}AuthCenter:Oidc:Test:ClientSecret"] = "secret";
        c[$"{prefix}AuthCenter:Oidc:Test:Scopes"] = "openid";
    }

    [Test]
    public async Task a_scheme_family_section_requires_its_package_Async()
    {
        // Without the Oidc package, its section is an unknown key of the AuthCenter's model: a configured family must not
        // silently do nothing.
        await StartMustFailAsync( "Unknown key 'CK-AppIdentity:Local:AuthCenter:Oidc'", c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            OidcScheme( c );
        }, local: true );

        // With the package, the family is a feature of the local party.
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
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
            c["Defaults:AuthCenter"] = "true";
        }, withOidc: true );
        var family = s.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();
        family.ProviderName.ShouldBe( "Oidc" );
        family.Schemes.ShouldBeEmpty( "It still hides the 'Oidc' provider name in the scheme listing." );
    }

    // A login provider whose payload is not an IOidcLoginPayload.
    sealed class NotOidcLoginProvider : ILoginProvider
    {
        public IReadOnlyCollection<string> ProviderNames => ["Oidc"];

        public object CreatePayload( string scheme ) => new object();

        public ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true ) => throw new NotSupportedException();
    }

    [TestCase( false, "There is no 'Oidc' login provider" )]
    [TestCase( true, "is not an IOidcLoginPayload (CK.AuthenticationInfo.Oidc)" )]
    public async Task an_Oidc_login_starts_only_when_it_can_be_completed_Async( bool withProvider, string message )
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            OidcScheme( c );
        }, withOidc: true, loginProvider: withProvider ? new NotOidcLoginProvider() : null );
        var family = (IAuthCenterRemoteScheme)s.GetRequiredFeature<LocalAuthCenter>().FindSchemeFamily( "Oidc.Test" ).ShouldNotBeNull();
        // The check is done before the provider is contacted (its discovery document is never read here).
        var start = await family.StartAsync( TestHelper.Monitor, "Oidc.Test", "state", "https://app.example.com/.auth/oidc/callback", critical: false );
        start.Url.ShouldBeNull();
        start.Error.ShouldNotBeNull().ShouldContain( message );
    }

    [Test]
    public async Task a_scheme_family_is_an_option_of_the_AuthCenter_that_false_disables_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Local:AuthCenter:Oidc"] = "false";
        }, withOidc: true );
        s.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldBeEmpty();
    }

    [Test]
    public async Task a_tenant_has_its_own_scheme_families_Async()
    {
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = "D/$App";
            c["Defaults:AuthCenter"] = "true";
            OidcScheme( c );
            c["Parties:0:FullName"] = "Acme/$Acme";
            OidcScheme( c, "Parties:0:Local:" );
            c["Parties:0:Local:AuthCenter:Oidc:Other:Authority"] = "https://other-idp.example.com";
            c["Parties:0:Local:AuthCenter:Oidc:Other:ClientId"] = "client";
            c["Parties:0:Local:AuthCenter:Oidc:Other:ClientSecret"] = "secret";
            c["Parties:0:Local:AuthCenter:Oidc:Other:Scopes"] = "openid";
        }, withOidc: true );
        var rootFamily = s.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();

        var acme = s.TenantDomains.Single();
        var acmeFamily = acme.GetRequiredFeature<LocalAuthCenter>().SchemeFamilies.ShouldHaveSingleItem();
        acmeFamily.ShouldNotBeSameAs( rootFamily );
        acmeFamily.Schemes.ShouldBe( ["Oidc.Test", "Oidc.Other"], ignoreOrder: true );
    }
}
