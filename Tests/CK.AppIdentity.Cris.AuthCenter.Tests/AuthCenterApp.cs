using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Passkey;
using CK.IO.Authentication.Weak;
using CK.Testing;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.AuthCenter.Tests;

/// <summary>
/// An AuthCenter application (CK.AppIdentity.Cris.AuthCenter.Local): its root (and the "Acme" tenant) is a local AuthCenter, with fakes for the providers
/// and the actors (CK.Testing.Cris.Authentication) and for the endpoint. The <see cref="Browser"/> plays the caller: it keeps what the endpoint issued
/// (the cookies) and the current authentication (what a front reads from the bearer token).
/// </summary>
public sealed class AuthCenterApp : IAsyncDisposable
{
    // The actors of the FakeActorDatabase (CK.Testing.Cris.Authentication): the applications have their own instance.
    static readonly FakeActorDatabase _actors = new FakeActorDatabase();

    public static ActorInfo Operator => _actors.Find( 42 )!;
    public static ActorInfo Albert => _actors.Find( 3712 )!;
    public static ActorInfo Robert => _actors.Find( 3713 )!;

    /// <summary>
    /// A login validator that accepts everything and records the user data of the last login.
    /// </summary>
    public sealed class RecordingLoginValidator : ILoginValidator
    {
        public static IReadOnlyDictionary<string, string?>? LastUserData;

        public ValueTask ValidateLoginAsync( IActivityMonitor monitor, ActorInfo loggedInActor, LoginContext context )
        {
            LastUserData = context.UserData;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Creates the account "Created" (77) for any unregistered identity, and counts its calls.
    /// </summary>
    public sealed class FakeAutoCreateAccount : IAutoCreateAccountService
    {
        public static int CallCount;

        public ValueTask<ActorLoginResult?> CreateAccountAndLoginAsync( IActivityMonitor monitor, LoginContext context )
        {
            ++CallCount;
            return ValueTask.FromResult<ActorLoginResult?>( ActorLoginResult.Success( new ActorInfo( 77, "Created", AuthLevel.Critical ) ) );
        }
    }

    public sealed class AllowImpersonation : IImpersonationService
    {
        readonly FakeActorDatabase _actors;

        public AllowImpersonation( FakeActorDatabase actors ) => _actors = actors;

        public ValueTask<ActorInfo?> ImpersonateAsync( IActivityMonitor monitor, AuthenticationInfo current, int actorId ) => ValueTask.FromResult( _actors.Find( actorId ) );
        public ValueTask<ActorInfo?> ImpersonateAsync( IActivityMonitor monitor, AuthenticationInfo current, string actorName ) => ValueTask.FromResult( _actors.Find( actorName ) );
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

        /// <summary>
        /// The callback URL of this browser's endpoint for the remote logins (null: it cannot receive them).
        /// </summary>
        public string? RemoteLoginCallbackUrl { get; set; } = "https://front.example.com/.auth/oidc/callback";

        /// <summary>
        /// The origin of the web page that sends the commands (null: not a web endpoint).
        /// </summary>
        public string? WebOrigin { get; set; } = "https://front.example.com";

        /// <summary>
        /// The hash of the remote login correlation secret (the "cookie" of a starting remote login).
        /// </summary>
        public string? RemoteLoginCorrelation { get; set; }

        internal string PrepareRemoteLogin() => RemoteLoginCorrelation = "correlation-hash-" + (++_count);

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

        public string? RemoteLoginCallbackUrl => _browser.RemoteLoginCallbackUrl;

        public string PrepareRemoteLogin() => _browser.PrepareRemoteLogin();

        public string? PresentedRemoteLoginHash => _browser.RemoteLoginCorrelation;

        public string? WebOrigin => _browser.WebOrigin;
    }

    public required AutomaticServices Services { get; init; }
    public required ApplicationIdentityService Identity { get; init; }
    public Browser Caller => Services.Services.GetRequiredService<Browser>();
    public CrisAuthCenter Center => Identity.GetRequiredFeature<CrisAuthCenter>();
    public LocalAuthCenter LocalCenter => Identity.GetRequiredFeature<LocalAuthCenter>();

    public ValueTask DisposeAsync() => Services.DisposeAsync();

    public static void LocalAuthCenter( MutableConfigurationSection c )
    {
        c["FullName"] = "D/$App";
        c["Defaults:AllowFeatures"] = "AuthCenter";
        c["Local:AuthCenter:TokenLifetime"] = "00:02:00";
        // The tenant is its own AuthCenter: the root's "Defaults" allow the feature.
        c["Parties:0:FullName"] = "Acme/$Acme";
    }

    public static async Task<AuthCenterApp> StartAsync( Action<MutableConfigurationSection>? configuration = null,
                                                        bool allowImpersonation = false,
                                                        bool recordLogins = false,
                                                        bool withOidc = true,
                                                        bool createAccounts = false,
                                                        bool withPasskeys = false )
    {
        var engine = TestHelper.CreateDefaultEngineConfiguration();
        engine.FirstBinPath.Types.Add( typeof( ApplicationIdentityService ),
                                       typeof( CurrentLocalParty ),
                                       typeof( CurrentLocalPartyDefaultProvider ),
                                       typeof( KeyManagementFeatureDriver ),
                                       typeof( DefaultCoreKeyStore ),
                                       typeof( AuthCenterFeatureDriver ),
                                       typeof( LocalAuthCenterFeatureDriver ),
                                       typeof( IAuthenticationSessionOpener ),
                                       // The endpoint side (CK.Cris.Authentication): the session commands are executed
                                       // by their endpoint, which executes the operations, handled here (single host).
                                       typeof( AuthenticationSessionEndpointService ),
                                       typeof( AuthenticationSessionHandlers ),
                                       typeof( AuthCenterOperationHandlers ),
                                       typeof( AuthCenterCommandHandlers ),
                                       typeof( ISessionOperationResult ),
                                       typeof( IOpenSessionOperationCommand ),
                                       typeof( IRefreshSessionOperationCommand ),
                                       typeof( ILogoutSessionOperationCommand ),
                                       typeof( IImpersonateOperationCommand ),
                                       typeof( IClearImpersonationOperationCommand ),
                                       typeof( IStartRemoteLoginOperationCommand ),
                                       typeof( ICompleteRemoteLoginOperationCommand ),
                                       typeof( CK.Auth.IAuthenticationTokenReader ),
                                       typeof( AuthCenterTokenReader ),
                                       typeof( IAuthenticationSessionEndpoint ),
                                       typeof( CrisAuthenticationService ),
                                       typeof( AuthenticationInfo ),
                                       typeof( AuthenticationInfoDefaultProvider ),
                                       typeof( FakeActorDatabase ),
                                       typeof( FakeWeakLoginProvider ),
                                       typeof( WeakLoginHandler ),
                                       typeof( FakeOidcLoginProvider ),
                                       // The handling validators (UserMessageCollector) need the current culture.
                                       typeof( NormalizedCultureInfoAmbientServiceDefault ),
                                       typeof( TranslationService ),
                                       typeof( NormalizedCultureInfo ),
                                       typeof( CurrentCultureInfo ),
                                       typeof( IStartLoginCommand ),
                                       typeof( IRemoteLoginCallbackCommand ),
                                       typeof( RawCrisExecutor ),
                                       typeof( CrisDirectory ),
                                       typeof( ICrisResultError ),
                                       typeof( IWeakLoginCommand ),
                                       typeof( IRefreshSessionCommand ),
                                       typeof( ILogoutSessionCommand ),
                                       typeof( IImpersonateCommand ),
                                       typeof( IClearImpersonationCommand ),
                                       typeof( IGetLoginSchemesQCommand ),
                                       typeof( ILoginSchemeInfo ),
                                       typeof( ISessionResult ),
                                       typeof( IAuthenticationInfoPoco ),
                                       typeof( IActorInfoPoco ) );
        if( allowImpersonation ) engine.FirstBinPath.Types.Add( typeof( AllowImpersonation ) );
        if( recordLogins ) engine.FirstBinPath.Types.Add( typeof( RecordingLoginValidator ) );
        if( createAccounts ) engine.FirstBinPath.Types.Add( typeof( FakeAutoCreateAccount ) );
        // The passkey scheme family (its package), the in-memory store and its "Passkey" provider.
        if( withPasskeys )
        {
            engine.FirstBinPath.Types.Add( typeof( Passkey.AuthCenterPasskeyFeatureDriver ),
                                           typeof( Passkey.AuthCenterPasskeyConfiguration ),
                                           typeof( Passkey.AuthCenterPasskeyHandlers ),
                                           typeof( PasskeyHandlers ),
                                           typeof( IStartPasskeyLoginOperationCommand ),
                                           typeof( IFinishPasskeyLoginOperationCommand ),
                                           typeof( IStartPasskeyRegistrationOperationCommand ),
                                           typeof( IFinishPasskeyRegistrationOperationCommand ),
                                           typeof( InMemoryPasskeyStore ),
                                           typeof( FakePasskeyLoginProvider ),
                                           typeof( IStartPasskeyLoginCommand ),
                                           typeof( IPasskeyLoginCommand ),
                                           typeof( IStartPasskeyRegistrationCommand ),
                                           typeof( IPasskeyRegistrationCommand ),
                                           typeof( IPasskeyRegistrationResult ) );
        }
        // The OpenID Connect scheme family (its package): without it, the AuthCenter core has no remote scheme.
        if( withOidc ) engine.FirstBinPath.Types.Add( typeof( Oidc.AuthCenterOidcFeatureDriver ), typeof( Oidc.AuthCenterOidcConfiguration ) );
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
