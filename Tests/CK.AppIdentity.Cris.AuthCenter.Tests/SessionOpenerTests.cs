using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Weak;
using CK.Testing;
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

/// <summary>
/// The local AuthCenter: a provider handler delegates to the <see cref="AuthCenterSessionOpener"/>.
/// </summary>
[TestFixture]
public class SessionOpenerTests
{
    static readonly ActorInfo _operator = new ActorInfo( 42, "Operator", AuthLevel.Unsafe, [new SchemeInfo( ActorInfo.WeakScheme, new DateTime( 2026, 1, 1, 0, 0, 0, DateTimeKind.Utc ) )] );

    public sealed class NoActor : IActorInfoProvider
    {
        public ValueTask<ActorInfo?> GetActorInfoAsync( IActivityMonitor monitor, int actorId ) => ValueTask.FromResult<ActorInfo?>( null );
    }

    /// <summary>
    /// A "Weak" provider whose payload is the command: only "Operator" exists.
    /// </summary>
    public sealed class FakeWeakLoginProvider : ILoginProvider
    {
        public IReadOnlyCollection<string> ProviderNames => [ActorInfo.WeakScheme];

        public object CreatePayload( string scheme ) => throw new ArgumentException( "No payload." );

        public ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
        {
            var cmd = (IWeakLoginCommand)payload;
            return ValueTask.FromResult( cmd.WeakActorName == "Operator"
                                            ? ActorLoginResult.Success( _operator )
                                            : ActorLoginResult.Failure( 3, "Invalid user name or identifier." ) );
        }

        // "I implement an authentication provider, I handle its login commands."
        [CommandHandler]
        public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IWeakLoginCommand cmd, IAuthenticationSessionOpener opener )
            => opener.OpenSessionAsync( monitor, cmd, ActorInfo.WeakScheme, cmd, rememberMe: true );
    }

    public sealed class FakeEndpoint : IAuthenticationSessionEndpoint
    {
        public AuthenticationSessionProof? PresentedProof => null;

        public List<(bool RememberMe, DateTime RefreshExpires)> Issued { get; } = new();

        public AuthenticationSessionProof Issue( bool rememberMe, DateTime refreshExpires )
        {
            Issued.Add( (rememberMe, refreshExpires) );
            return new AuthenticationSessionProof( "refresh-hash-" + Issued.Count, "binding-hash-" + Issued.Count );
        }

        public void Clear() { }
    }

    sealed class App : IAsyncDisposable
    {
        public required AutomaticServices Services { get; init; }
        public required ApplicationIdentityService Identity { get; init; }
        public ValueTask DisposeAsync() => Services.DisposeAsync();
    }

    static async Task<App> StartAsync( Action<MutableConfigurationSection> configuration )
    {
        var engine = TestHelper.CreateDefaultEngineConfiguration();
        engine.FirstBinPath.Types.Add( typeof( ApplicationIdentityService ),
                                       typeof( CurrentLocalParty ),
                                       typeof( CurrentLocalPartyDefaultProvider ),
                                       typeof( KeyManagementFeatureDriver ),
                                       typeof( DefaultCoreKeyStore ),
                                       typeof( AuthCenterFeatureDriver ),
                                       typeof( IAuthenticationSessionOpener ),
                                       typeof( AuthCenterSessionOpener ),
                                       typeof( IAuthenticationSessionEndpoint ),
                                       typeof( CrisAuthenticationService ),
                                       typeof( AuthenticationInfo ),
                                       typeof( AuthenticationInfoDefaultProvider ),
                                       typeof( NoActor ),
                                       typeof( FakeWeakLoginProvider ),
                                       typeof( RawCrisExecutor ),
                                       typeof( CrisDirectory ),
                                       typeof( ICrisResultError ),
                                       typeof( IWeakLoginCommand ),
                                       typeof( ISessionResult ),
                                       typeof( IAuthenticationInfoPoco ),
                                       typeof( IActorInfoPoco ) );
        var r = await engine.RunSuccessfullyAsync();
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration ).ShouldNotBeNull();
        var services = r.CreateAutomaticServices( configureServices: services =>
        {
            services.AddSingleton( c );
            services.AddSingleton<IDataProtectionProvider>( FakeProtector.Fake );
            services.AddScoped<FakeEndpoint>();
            services.AddScoped<IAuthenticationSessionEndpoint>( sp => sp.GetRequiredService<FakeEndpoint>() );
            services.AddScoped( sp => AuthenticationInfo.None );
            services.AddScoped<IActivityMonitor>( sp => TestHelper.Monitor );
            services.AddScoped( sp => new CurrentLocalParty( sp.GetRequiredService<ApplicationIdentityService>() ) );
        } );
        var identity = services.Services.GetRequiredService<ApplicationIdentityService>();
        _ = ((IHostedService)identity).StartAsync( default );
        await identity.InitializationTask;
        return new App { Services = services, Identity = identity };
    }

    static void LocalAuthCenter( MutableConfigurationSection c )
    {
        c["FullName"] = "D/$App";
        c["AllowFeatures"] = "AuthCenter";
        c["AuthCenter:TokenLifetime"] = "00:02:00";
        c["Parties:0:FullName"] = "Acme/$Acme";
        c["Parties:0:AuthCenter"] = "true";
    }

    [Test]
    public async Task a_login_opens_a_session_and_returns_a_signed_token_Async()
    {
        await using var app = await StartAsync( LocalAuthCenter );
        var center = app.Identity.GetRequiredFeature<CrisAuthCenter>();
        center.Local.ShouldNotBeNull().Options.TokenLifetime.ShouldBe( TimeSpan.FromMinutes( 2 ) );

        await using var scope = app.Services.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var login = services.GetRequiredService<PocoDirectory>().Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" );
        var r = (ISessionResult)(await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, login )).Result!;

        r.Success.ShouldBeTrue();
        r.RememberMe.ShouldBeTrue();
        r.Info.UnsafeActor.ActorId.ShouldBe( 42 );
        r.Info.UnsafeActor.Level.ShouldBe( AuthLevel.Unsafe );
        r.Info.DeviceId.ShouldNotBeNullOrEmpty();
        var endpoint = services.GetRequiredService<FakeEndpoint>();
        endpoint.Issued.ShouldHaveSingleItem().RememberMe.ShouldBeTrue();

        // The token is read back by the AuthCenter (this is what a front does): it holds the session.
        center.TryReadToken( TestHelper.Monitor, r.Token.ShouldNotBeNull(), DateTime.UtcNow, out var info, out var sessionId ).ShouldBeTrue();
        info.UnsafeActor.ActorId.ShouldBe( 42 );
        info.UnsafeActor.ActorName.ShouldBe( "Operator" );
        info.UnsafeActor.Level.ShouldBe( AuthLevel.Unsafe );
        info.DeviceId.ShouldBe( r.Info.DeviceId );
        info.Expires.ShouldNotBeNull().ShouldBeLessThanOrEqualTo( DateTime.UtcNow.AddMinutes( 2 ), "The authentication cannot outlive the token." );

        // The session is stored with the hashes of the endpoint secrets.
        var session = (await center.Local.Sessions.TryReadAsync( TestHelper.Monitor, 42, sessionId )).ShouldNotBeNull();
        session.RefreshSecretHash.ShouldBe( "refresh-hash-1" );
        session.BindingSecretHash.ShouldBe( "binding-hash-1" );
        session.RememberMe.ShouldBeTrue();
        session.Expires.ShouldBe( endpoint.Issued[0].RefreshExpires );
        center.Local.Sessions.TryDelete( TestHelper.Monitor, 42, sessionId ).ShouldBeTrue();
    }

    [Test]
    public async Task a_failed_login_opens_nothing_Async()
    {
        await using var app = await StartAsync( LocalAuthCenter );
        await using var scope = app.Services.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var login = services.GetRequiredService<PocoDirectory>().Create<IWeakLoginCommand>( c => c.WeakActorName = "Nobody" );
        var r = (ISessionResult)(await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, login )).Result!;

        r.Success.ShouldBeFalse();
        r.Token.ShouldBeNull();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.LoginFailed" );
        services.GetRequiredService<FakeEndpoint>().Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task with_a_remote_AuthCenter_nothing_is_opened_here_Async()
    {
        await using var app = await StartAsync( c =>
        {
            c["FullName"] = "D/$Front";
            c["AllowFeatures"] = "AuthCenter";
            c["Parties:0:PartyName"] = "Center";
            c["Parties:0:AuthCenter"] = "true";
        } );
        app.Identity.GetRequiredFeature<CrisAuthCenter>().Local.ShouldBeNull();
        await using var scope = app.Services.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var login = services.GetRequiredService<PocoDirectory>().Create<IWeakLoginCommand>( c => c.WeakActorName = "Operator" );
        var r = (ISessionResult)(await services.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( services, login )).Result!;

        // The relay is done by the endpoint, before the handlers: a session command that reaches the opener fails closed.
        r.Success.ShouldBeFalse();
        r.Token.ShouldBeNull();
        r.UserMessages.ShouldHaveSingleItem().ResName.ShouldBe( "Authentication.RemoteAuthCenter" );
        services.GetRequiredService<FakeEndpoint>().Issued.ShouldBeEmpty();
    }

    [Test]
    public async Task tokens_are_bound_to_their_local_party_and_cannot_be_tampered_Async()
    {
        await using var app = await StartAsync( LocalAuthCenter );
        var root = app.Identity.GetRequiredFeature<CrisAuthCenter>();
        var acme = app.Identity.TenantDomains.Single().GetRequiredFeature<CrisAuthCenter>();
        acme.IsLocal.ShouldBeTrue( "This application is the AuthCenter of the tenant too." );

        // An impersonation at Critical level: everything goes through the token.
        var utcNow = DateTime.UtcNow;
        var albert = new ActorInfo( 3712, "Albert", AuthLevel.Critical );
        var paula = new ActorInfo( 12, "Paula", AuthLevel.Critical );
        var auth = AuthenticationInfo.Create( albert, paula, utcNow.AddDays( 1 ), utcNow.AddHours( 1 ), "Device", utcNow );
        var sessionId = AuthCenterSession.NewSessionId();
        var token = root.Local.ShouldNotBeNull().CreateToken( sessionId, auth, utcNow );

        root.TryReadToken( TestHelper.Monitor, token, utcNow, out var info, out var readId ).ShouldBeTrue();
        readId.ShouldBe( sessionId );
        info.IsImpersonated.ShouldBeTrue();
        info.UnsafeActualActor.ActorName.ShouldBe( "Albert" );
        info.UnsafeActor.ActorName.ShouldBe( "Paula" );
        info.Actor.Level.ShouldBe( AuthLevel.Critical );
        info.CriticalExpires.ShouldNotBeNull().ShouldBeLessThanOrEqualTo( utcNow.AddMinutes( 2 ), "Clamped by the token (2 minutes)." );

        acme.TryReadToken( TestHelper.Monitor, token, utcNow, out _, out _ ).ShouldBeFalse( "Another local party: other keys, other audience." );

        var bytes = System.Buffers.Text.Base64Url.DecodeFromChars( token );
        bytes[10] ^= 1;
        root.TryReadToken( TestHelper.Monitor, System.Buffers.Text.Base64Url.EncodeToString( bytes ), utcNow, out _, out _ ).ShouldBeFalse();
        root.TryReadToken( TestHelper.Monitor, "not a token", utcNow, out _, out _ ).ShouldBeFalse();
        root.TryReadToken( TestHelper.Monitor, token, utcNow.AddMinutes( 3 ), out _, out _ ).ShouldBeFalse( "Expired." );
    }
}
