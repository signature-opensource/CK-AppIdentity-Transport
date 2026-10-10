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
    }

    /// <summary>
    /// A "Basic" provider (its payload is the IBasicLoginCommand): Albert's password is "secret". It records the password it receives.
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
    }

    /// <summary>
    /// The payload of the fake "Oidc" provider (like the IUserOidcInfo of CK.DB.User.UserOidc).
    /// </summary>
    public sealed class OidcPayload
    {
        public string SchemeSuffix { get; set; } = "";
        public string Sub { get; set; } = "";
        public string Claims { get; set; } = "";
    }

    /// <summary>
    /// A fake "Oidc" provider: in the "Test" scheme, "albert-sub" is Albert and "paula-sub" is Paula (the actors bound
    /// to these identities). It records the last payload.
    /// </summary>
    public sealed class FakeOidcLoginProvider : ILoginProvider
    {
        public static OidcPayload? LastPayload;

        public IReadOnlyCollection<string> ProviderNames => ["Oidc"];

        public object CreatePayload( string scheme ) => new OidcPayload();

        public ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
        {
            var p = (OidcPayload)payload;
            LastPayload = p;
            var a = p.SchemeSuffix != "Test"
                        ? null
                        : p.Sub switch { "albert-sub" => Albert, "paula-sub" => Paula, _ => null };
            return ValueTask.FromResult( a != null ? ActorLoginResult.Success( a ) : ActorLoginResult.Failure( 5, "No actor is bound to this identity.", isUnregisteredUser: true ) );
        }
    }

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
    /// The passkey storage, in memory.
    /// </summary>
    public sealed class InMemoryPasskeyStore : IPasskeyStore
    {
        readonly Dictionary<string, PasskeyCredential> _credentials = new();
        readonly Dictionary<int, byte[]> _handles = new();

        public IReadOnlyCollection<PasskeyCredential> All => _credentials.Values;

        static string Key( ReadOnlyMemory<byte> id ) => Convert.ToHexString( id.Span );

        public ValueTask<ReadOnlyMemory<byte>> GetOrCreateUserHandleAsync( IActivityMonitor monitor, int actorId )
        {
            lock( _handles )
            {
                if( !_handles.TryGetValue( actorId, out var h ) ) _handles.Add( actorId, h = System.Security.Cryptography.RandomNumberGenerator.GetBytes( 32 ) );
                return ValueTask.FromResult<ReadOnlyMemory<byte>>( h );
            }
        }

        public ValueTask<PasskeyCredential?> FindAsync( IActivityMonitor monitor, ReadOnlyMemory<byte> credentialId )
        {
            lock( _credentials ) return ValueTask.FromResult( _credentials.GetValueOrDefault( Key( credentialId ) ) );
        }

        public ValueTask<IReadOnlyList<PasskeyCredential>> GetCredentialsAsync( IActivityMonitor monitor, int actorId )
        {
            lock( _credentials ) return ValueTask.FromResult<IReadOnlyList<PasskeyCredential>>( _credentials.Values.Where( c => c.ActorId == actorId ).ToList() );
        }

        public ValueTask<bool> CreateAsync( IActivityMonitor monitor, PasskeyCredential credential )
        {
            lock( _credentials ) return ValueTask.FromResult( _credentials.TryAdd( Key( credential.CredentialId ), credential ) );
        }

        // What the "Passkey" provider does on an actual login.
        internal void Update( PasskeyLoginPayload p )
        {
            lock( _credentials )
            {
                var c = _credentials[Key( p.CredentialId )];
                _credentials[Key( p.CredentialId )] = new PasskeyCredential( c.CredentialId, c.ActorId, c.UserHandle, c.PublicKey, p.SignCount, c.BackupEligible, p.BackupState, c.Aaguid, c.Transports, c.Name );
            }
        }
    }

    /// <summary>
    /// The "Passkey" provider of the <see cref="InMemoryPasskeyStore"/>.
    /// </summary>
    public sealed class FakePasskeyLoginProvider : ILoginProvider
    {
        readonly InMemoryPasskeyStore _store;

        public FakePasskeyLoginProvider( InMemoryPasskeyStore store ) => _store = store;

        public IReadOnlyCollection<string> ProviderNames => [PasskeyLoginPayload.Scheme];

        public object CreatePayload( string scheme ) => throw new ArgumentException( "No payload." );

        public async ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
        {
            var p = (PasskeyLoginPayload)payload;
            var c = await _store.FindAsync( monitor, p.CredentialId );
            var a = c != null ? Find( c.ActorId ) : null;
            if( a == null ) return ActorLoginResult.Failure( 6, "Unknown passkey." );
            if( actualLogin ) _store.Update( p );
            return ActorLoginResult.Success( a );
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

    public ValueTask DisposeAsync() => Services.DisposeAsync();

    public static void LocalAuthCenter( MutableConfigurationSection c )
    {
        c["FullName"] = "D/$App";
        c["AllowFeatures"] = "AuthCenter";
        c["AuthCenter:TokenLifetime"] = "00:02:00";
        c["Parties:0:FullName"] = "Acme/$Acme";
        c["Parties:0:AuthCenter"] = "true";
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
                                       typeof( IAuthenticationSessionOpener ),
                                       typeof( AuthCenterSessionOpener ),
                                       typeof( AuthCenterSessionService ),
                                       typeof( AuthCenterCommandHandlers ),
                                       typeof( CK.Auth.IAuthenticationTokenReader ),
                                       typeof( AuthCenterTokenReader ),
                                       typeof( IAuthenticationSessionEndpoint ),
                                       typeof( CrisAuthenticationService ),
                                       typeof( AuthenticationInfo ),
                                       typeof( AuthenticationInfoDefaultProvider ),
                                       typeof( FakeActors ),
                                       typeof( FakeWeakLoginProvider ),
                                       typeof( AuthCenterWeakLoginHandler ),
                                       typeof( FakeOidcLoginProvider ),
                                       typeof( AuthCenterRemoteLoginHandlers ),
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
