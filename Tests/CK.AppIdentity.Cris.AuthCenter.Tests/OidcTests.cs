using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.Monitoring;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// The OpenID Connect logins of a local AuthCenter (<see cref="AuthCenterOidc"/>, <see cref="AuthCenterOidcHandlers"/>)
/// against the <see cref="FakeIdentityProvider"/>.
/// </summary>
[TestFixture]
public class OidcTests
{
    const string Callback = "https://front.example.com/.auth/oidc/callback";

    static Action<MutableConfigurationSection> Configuration( FakeIdentityProvider idp, Action<MutableConfigurationSection>? more = null )
    {
        return c =>
        {
            AuthCenterApp.LocalAuthCenter( c );
            c["AuthCenter:Oidc:Test:Authority"] = idp.BaseUrl;
            c["AuthCenter:Oidc:Test:ClientId"] = FakeIdentityProvider.ClientId;
            c["AuthCenter:Oidc:Test:ClientSecret"] = FakeIdentityProvider.ClientSecret;
            c["AuthCenter:Oidc:Test:Scopes"] = "openid profile";
            c["AuthCenter:Oidc:Test:CallbackUrls:0"] = Callback;
            more?.Invoke( c );
        };
    }

    static async Task<object?> StartAsync( AuthCenterApp app, string scheme = "Oidc.Test", string? returnUrl = "/home", bool rememberMe = true )
    {
        return await app.ExecuteAsync( p => p.Create<IStartLoginCommand>( c =>
        {
            c.Scheme = scheme;
            c.ReturnUrl = returnUrl;
            c.RememberMe = rememberMe;
            c.InlineMode = true;
        } ) );
    }

    static Task<ISessionResult> CallbackAsync( AuthCenterApp app, string state, string code, string? error = null )
    {
        return app.ExecuteSessionAsync( p => p.Create<IRemoteLoginCallbackCommand>( c =>
        {
            c.State = state;
            c.Code = code;
            c.Error = error;
        } ) );
    }

    static IEnumerable<string> Errors( object? result ) => result.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().Errors.Select( e => e.Text );

    [Test]
    public async Task an_oidc_login_opens_a_session_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );

        var start = (RedirectedUrl)(await StartAsync( app )).ShouldNotBeNull();
        start.IsInline.ShouldBeTrue();
        start.Url.ShouldStartWith( idp.BaseUrl + "/authorize?" );
        start.Url.ShouldContain( "scope=openid%20profile" );
        start.Url.ShouldContain( "redirect_uri=" + Uri.EscapeDataString( Callback ) );
        app.Caller.RemoteLoginCorrelation.ShouldNotBeNull( "The endpoint prepared the correlation." );
        app.Center.Local.ShouldNotBeNull().Oidc.PendingLoginCount.ShouldBe( 1 );

        var (redirect, code, state) = idp.Authorize( start.Url, "albert-sub" );
        redirect.ShouldBe( Callback );
        var r = await CallbackAsync( app, state, code );
        r.Success.ShouldBeTrue();
        r.RememberMe.ShouldBeTrue();
        r.Info.UnsafeActor.ActorName.ShouldBe( "Albert" );
        app.Caller.Current.Actor.ActorName.ShouldBe( "Albert" );
        var payload = AuthCenterApp.FakeOidcLoginProvider.LastPayload.ShouldNotBeNull();
        payload.SchemeSuffix.ShouldBe( "Test" );
        payload.Sub.ShouldBe( "albert-sub" );
        app.Center.Local.Oidc.PendingLoginCount.ShouldBe( 0, "The pending login is consumed." );

        // A replayed callback finds no pending login.
        var replay = await CallbackAsync( app, state, code );
        replay.Success.ShouldBeFalse();
        replay.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteLoginExpired" );
        idp.RedeemCount.ShouldBe( 1 );
    }

    [Test]
    public async Task an_unbound_identity_cannot_log_in_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );
        var start = (RedirectedUrl)(await StartAsync( app )).ShouldNotBeNull();
        var (_, code, state) = idp.Authorize( start.Url, "nobody-sub" );
        var r = await CallbackAsync( app, state, code );
        r.Success.ShouldBeFalse();
        r.Token.ShouldBeNull();
        app.Caller.Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task a_login_can_only_be_completed_by_the_caller_that_started_it_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );
        var start = (RedirectedUrl)(await StartAsync( app )).ShouldNotBeNull();
        var (_, code, state) = idp.Authorize( start.Url, "albert-sub" );

        // Login CSRF: the code and the state of the attacker's login reach the victim's browser, that has another correlation.
        app.Caller.RemoteLoginCorrelation = "another-browser";
        var r = await CallbackAsync( app, state, code );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteLoginCorrelation" );
        idp.RedeemCount.ShouldBe( 0, "The code is not redeemed." );
        app.Caller.Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task the_provider_error_is_a_failure_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );
        var start = (RedirectedUrl)(await StartAsync( app )).ShouldNotBeNull();
        var (_, _, state) = idp.Authorize( start.Url, "albert-sub" );
        var r = await CallbackAsync( app, state, "", "access_denied" );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteLoginRefused" );
    }

    [TestCase( "issuer" )]
    [TestCase( "audience" )]
    [TestCase( "nonce" )]
    [TestCase( "at_hash" )]
    public async Task an_invalid_identity_token_is_refused_Async( string what )
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );
        switch( what )
        {
            case "issuer": idp.TokenIssuer = "https://evil.example.com"; break;
            case "audience": idp.TokenAudience = "another-client"; break;
            case "nonce": idp.TokenNonce = "a-replayed-nonce"; break;
            case "at_hash": idp.TokenAtHash = "not-the-hash-of-the-access-token"; break;
        }
        var start = (RedirectedUrl)(await StartAsync( app )).ShouldNotBeNull();
        var (_, code, state) = idp.Authorize( start.Url, "albert-sub" );
        var r = await CallbackAsync( app, state, code );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteLoginFailed" );
        app.Caller.Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task the_start_is_validated_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );

        Errors( await StartAsync( app, scheme: "Oidc.Unknown" ) ).ShouldContain( "Unknown login scheme 'Oidc.Unknown'." );
        Errors( await StartAsync( app, returnUrl: "https://evil.example.com/" ) ).ShouldContain( "The return URL must be a relative path." );
        Errors( await StartAsync( app, returnUrl: "//evil.example.com/" ) ).ShouldContain( "The return URL must be a relative path." );

        app.Caller.RemoteLoginCallbackUrl = "https://other-front.example.com/.auth/oidc/callback";
        Errors( await StartAsync( app ) ).ShouldContain( "The callback 'https://other-front.example.com/.auth/oidc/callback' is not allowed for the scheme 'Oidc.Test'." );
        app.Caller.RemoteLoginCallbackUrl = null;
        Errors( await StartAsync( app ) ).ShouldContain( "This endpoint cannot receive remote logins." );

        app.Center.Local.ShouldNotBeNull().Oidc.PendingLoginCount.ShouldBe( 0 );
    }

    [Test]
    public async Task the_issuer_announced_by_the_provider_must_be_the_configured_one_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp, c => c["AuthCenter:Oidc:Test:Issuer"] = "https://expected.example.com" ) );
        using( TestHelper.Monitor.CollectTexts( out var texts ) )
        {
            (await StartAsync( app )).ShouldBeAssignableTo<ICrisResultError>();
            texts.ShouldContain( t => t.Contains( "announces the issuer" ) );
        }
    }

    [Test]
    public async Task the_oidc_schemes_are_listed_Async()
    {
        using var idp = new FakeIdentityProvider();
        await using var app = await AuthCenterApp.StartAsync( Configuration( idp ) );
        var schemes = (IList<string>)(await app.ExecuteAsync( p => p.Create<IGetLoginSchemesQCommand>() )).ShouldNotBeNull();
        schemes.ShouldContain( "Oidc.Test" );
        schemes.ShouldNotContain( "Oidc" );
    }

    [TestCase( "Authority", "ftp://idp.example.com", "'Authority' must be an absolute https URL" )]
    [TestCase( "Authority", "http://idp.example.com", "'Authority' must be an absolute https URL" )]
    [TestCase( "ClientSecret", "", "'ClientSecret' is required." )]
    [TestCase( "CallbackUrls:0", "https://front.example.com/cb?x=1", "without query nor fragment" )]
    public async Task invalid_oidc_configurations_are_errors_Async( string key, string value, string message )
    {
        using var idp = new FakeIdentityProvider();
        using var logs = GrandOutput.Default.ShouldNotBeNull().CreateMemoryCollector( 200 );
        await Should.ThrowAsync<Exception>( () => AuthCenterApp.StartAsync( Configuration( idp, c => c[$"AuthCenter:Oidc:Test:{key}"] = value ) ) );
        await AuthCenterFeatureTests.ShouldLogAsync( logs, message );
    }
}
