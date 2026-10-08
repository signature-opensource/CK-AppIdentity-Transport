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
using Shouldly;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// An application whose root (and the "Acme" tenant) is a local AuthCenter, with fakes for the providers,
/// the actors and the endpoint. The <see cref="Browser"/> plays the caller: it keeps what the endpoint issued
/// (the cookies) and the current authentication (what a front reads from the bearer token).
/// </summary>
public sealed class AuthCenterApp : IAsyncDisposable
{
    public static readonly ActorInfo Operator = new ActorInfo( 42, "Operator", AuthLevel.Unsafe, [new SchemeInfo( ActorInfo.WeakScheme, new DateTime( 2026, 1, 1, 0, 0, 0, DateTimeKind.Utc ) )] );
    public static readonly ActorInfo Albert = new ActorInfo( 3712, "Albert", AuthLevel.Critical );
    public static readonly ActorInfo Paula = new ActorInfo( 12, "Paula", AuthLevel.Critical );

    public static ActorInfo? Find( int actorId ) => actorId switch { 42 => Operator, 3712 => Albert, 12 => Paula, _ => null };
    public static ActorInfo? Find( string name ) => name switch { "Operator" => Operator, "Albert" => Albert, "Paula" => Paula, _ => null };

    public sealed class FakeActors : IActorInfoProvider
    {
        public static readonly HashSet<int> Disabled = new();

        public ValueTask<ActorInfo?> GetActorInfoAsync( IActivityMonitor monitor, int actorId )
            => ValueTask.FromResult( Disabled.Contains( actorId ) ? null : Find( actorId ) );
    }

    /// <summary>
    /// A "Weak" provider whose payload is the command (any known actor, to test the session mechanics).
    /// </summary>
    public sealed class FakeWeakLoginProvider : ILoginProvider
    {
        public IReadOnlyCollection<string> ProviderNames => [ActorInfo.WeakScheme];

        public object CreatePayload( string scheme ) => throw new ArgumentException( "No payload." );

        public ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
        {
            var a = Find( ((IWeakLoginCommand)payload).WeakActorName );
            return ValueTask.FromResult( a != null ? ActorLoginResult.Success( a ) : ActorLoginResult.Failure( 3, "Invalid user name or identifier." ) );
        }

        // "I implement an authentication provider, I handle its login commands."
        [CommandHandler]
        public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IWeakLoginCommand cmd, IAuthenticationSessionOpener opener )
            => opener.OpenSessionAsync( monitor, cmd, ActorInfo.WeakScheme, cmd, rememberMe: true );
    }

    /// <summary>
    /// A "Basic" provider whose payload is the command: Albert's password is "secret". It records the password it receives.
    /// </summary>
    public sealed class FakeBasicLoginProvider : ILoginProvider
    {
        public static string? LastPassword;

        public IReadOnlyCollection<string> ProviderNames => ["Basic"];

        public object CreatePayload( string scheme ) => throw new ArgumentException( "No payload." );

        public ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
        {
            var cmd = (CK.IO.Authentication.Basic.IBasicLoginCommand)payload;
            LastPassword = cmd.Password;
            return ValueTask.FromResult( cmd.UserName == "Albert" && cmd.Password == "secret"
                                            ? ActorLoginResult.Success( Albert )
                                            : ActorLoginResult.Failure( 4, "Invalid credentials." ) );
        }

        [CommandHandler]
        public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, CK.IO.Authentication.Basic.IBasicLoginCommand cmd, IAuthenticationSessionOpener opener )
            => opener.OpenSessionAsync( monitor, cmd, "Basic", cmd, cmd.RememberMe );
    }

    public sealed class AllowImpersonation : IImpersonationService
    {
        public ValueTask<ActorInfo?> ImpersonateAsync( IActivityMonitor monitor, AuthenticationInfo current, int actorId ) => ValueTask.FromResult( Find( actorId ) );
        public ValueTask<ActorInfo?> ImpersonateAsync( IActivityMonitor monitor, AuthenticationInfo current, string actorName ) => ValueTask.FromResult( Find( actorName ) );
    }

    public sealed class Browser
    {
        int _count;

        public AuthenticationSessionProof? Cookies { get; set; }

        public List<(string SessionKey, bool RememberMe, DateTime RefreshExpires)> Issued { get; } = new();

        public int ClearCount { get; private set; }

        public AuthenticationInfo Current { get; set; } = AuthenticationInfo.None;

        public string? Token { get; set; }

        (string, string)? _prepared;

        internal (string, string) PrepareSecrets()
        {
            ++_count;
            var p = ("refresh-hash-" + _count, "binding-hash-" + _count);
            _prepared = p;
            return p;
        }

        internal AuthenticationSessionProof Issue( string sessionKey, bool rememberMe, DateTime refreshExpires )
        {
            Issued.Add( (sessionKey, rememberMe, refreshExpires) );
            var (refresh, binding) = _prepared ?? PrepareSecrets();
            _prepared = null;
            return Cookies = new AuthenticationSessionProof( sessionKey, refresh, binding );
        }

        internal void Clear()
        {
            ++ClearCount;
            Cookies = null;
        }
    }

    public sealed class FakeEndpoint : IAuthenticationSessionEndpoint
    {
        readonly Browser _browser;

        public FakeEndpoint( Browser browser ) => _browser = browser;

        public AuthenticationSessionProof? PresentedProof => _browser.Cookies;

        public string? PresentedToken => _browser.Token;

        public (string RefreshSecretHash, string BindingSecretHash) PrepareSecrets() => _browser.PrepareSecrets();

        public AuthenticationSessionProof Issue( string sessionKey, bool rememberMe, DateTime refreshExpires ) => _browser.Issue( sessionKey, rememberMe, refreshExpires );

        public void Clear() => _browser.Clear();
    }

    public required AutomaticServices Services { get; init; }
    public required ApplicationIdentityService Identity { get; init; }
    public Browser Caller => Services.Services.GetRequiredService<Browser>();
    public CrisAuthCenter Center => Identity.GetRequiredFeature<CrisAuthCenter>();

    public ValueTask DisposeAsync() => Services.DisposeAsync();

    public static void LocalAuthCenter( MutableConfigurationSection c )
    {
        c["FullName"] = "D/$App";
        c["AllowFeatures"] = "AuthCenter";
        c["AuthCenter:TokenLifetime"] = "00:02:00";
        c["Parties:0:FullName"] = "Acme/$Acme";
        c["Parties:0:AuthCenter"] = "true";
    }

    public static async Task<AuthCenterApp> StartAsync( Action<MutableConfigurationSection>? configuration = null, bool allowImpersonation = false )
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
                                       typeof( AuthCenterSessionService ),
                                       typeof( AuthCenterCommandHandlers ),
                                       typeof( IAuthenticationSessionEndpoint ),
                                       typeof( CrisAuthenticationService ),
                                       typeof( AuthenticationInfo ),
                                       typeof( AuthenticationInfoDefaultProvider ),
                                       typeof( FakeActors ),
                                       typeof( FakeWeakLoginProvider ),
                                       typeof( RawCrisExecutor ),
                                       typeof( CrisDirectory ),
                                       typeof( ICrisResultError ),
                                       typeof( IWeakLoginCommand ),
                                       typeof( IRefreshSessionCommand ),
                                       typeof( ILogoutSessionCommand ),
                                       typeof( IImpersonateCommand ),
                                       typeof( IClearImpersonationCommand ),
                                       typeof( IGetLoginSchemesQCommand ),
                                       typeof( ISessionResult ),
                                       typeof( IAuthenticationInfoPoco ),
                                       typeof( IActorInfoPoco ) );
        if( allowImpersonation ) engine.FirstBinPath.Types.Add( typeof( AllowImpersonation ) );
        var r = await engine.RunSuccessfullyAsync();
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration ?? LocalAuthCenter ).ShouldNotBeNull();
        var services = r.CreateAutomaticServices( configureServices: services =>
        {
            services.AddSingleton( c );
            services.AddSingleton<IDataProtectionProvider>( FakeProtector.Fake );
            services.AddSingleton<Browser>();
            services.AddScoped<IAuthenticationSessionEndpoint, FakeEndpoint>();
            services.AddScoped( sp => sp.GetRequiredService<Browser>().Current );
            services.AddScoped<IActivityMonitor>( sp => TestHelper.Monitor );
            services.AddScoped( sp => new CurrentLocalParty( sp.GetRequiredService<ApplicationIdentityService>() ) );
        } );
        var identity = services.Services.GetRequiredService<ApplicationIdentityService>();
        _ = ((IHostedService)identity).StartAsync( default );
        await identity.InitializationTask;
        return new AuthCenterApp { Services = services, Identity = identity };
    }

    /// <summary>
    /// Executes a command in a new scope (a request of the <see cref="Caller"/>).
    /// </summary>
    public async Task<object?> ExecuteAsync( Func<PocoDirectory, IAbstractCommand> create )
    {
        await using var scope = Services.Services.CreateAsyncScope();
        var s = scope.ServiceProvider;
        var cmd = create( s.GetRequiredService<PocoDirectory>() );
        return (await s.GetRequiredService<RawCrisExecutor>().RawExecuteAsync( s, cmd )).Result;
    }

    public async Task<ISessionResult> ExecuteSessionAsync( Func<PocoDirectory, IAbstractCommand> create )
    {
        var r = (ISessionResult)(await ExecuteAsync( create )).ShouldNotBeNull();
        // Like a front: the token becomes the current authentication.
        if( r.Token != null )
        {
            Caller.Current = (await Center.ReadTokenAsync( TestHelper.Monitor, r.Token, DateTime.UtcNow )).ShouldNotBeNull().Info;
            Caller.Token = r.Token;
        }
        return r;
    }

    public Task<ISessionResult> LoginAsync( string name ) => ExecuteSessionAsync( p => p.Create<IWeakLoginCommand>( c => c.WeakActorName = name ) );
}
