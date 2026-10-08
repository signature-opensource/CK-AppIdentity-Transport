using CK.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The OpenID Connect client of a <see cref="LocalAuthCenter"/> (authorization code flow with PKCE). It alone holds
/// the client secrets: the fronts only relay the start of a login and the callback.
/// <list type="number">
///   <item>
///   <see cref="StartAsync"/> creates a <b>pending login</b> (state, nonce, PKCE verifier, the callback URL and the hash
///   of the correlation secret of the endpoint) and returns the authorization URL.
///   </item>
///   <item>
///   <see cref="CompleteAsync"/> consumes the pending login (one use), checks the correlation and the expiration,
///   exchanges the code and validates the identity token (signature, issuer, audience, lifetime, nonce).
///   </item>
/// </list>
/// The pending logins live in memory (a restart cancels the logins in progress) for <see cref="PendingLoginLifetime"/>,
/// and there are at most <see cref="MaxPendingLogins"/> of them.
/// </summary>
public sealed class AuthCenterOidc
{
    /// <summary>
    /// The lifetime of a pending login: 10 minutes.
    /// </summary>
    public static readonly TimeSpan PendingLoginLifetime = TimeSpan.FromMinutes( 10 );

    /// <summary>
    /// The maximal number of pending logins: 10,000. Starting a login is anonymous: this bounds the memory.
    /// </summary>
    public const int MaxPendingLogins = 10_000;

    readonly HttpClient _http;
    readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _configurations;
    readonly ConcurrentDictionary<string, PendingLogin> _pending;

    sealed record PendingLogin( OidcSchemeOptions Scheme,
                                string CallbackUrl,
                                string CorrelationHash,
                                string Nonce,
                                string CodeVerifier,
                                bool RememberMe,
                                DateTime Expires );

    /// <summary>
    /// The result of a <see cref="CompleteAsync"/>: the scheme and the subject on success, the error otherwise.
    /// </summary>
    /// <param name="Scheme">The scheme of the login (null when the pending login cannot be found).</param>
    /// <param name="Sub">The subject: the identifier of the user at the provider. Null on error.</param>
    /// <param name="RememberMe">Whether the session must be remembered.</param>
    /// <param name="Error">The error text. Null on success.</param>
    /// <param name="ErrorId">The error resource name. Null on success.</param>
    public readonly record struct Completion( OidcSchemeOptions? Scheme, string? Sub, bool RememberMe, string? Error, string? ErrorId )
    {
        /// <summary>
        /// Gets whether the login succeeded.
        /// </summary>
        public bool Success => Error == null;
    }

    internal AuthCenterOidc()
    {
        _http = new HttpClient() { Timeout = TimeSpan.FromSeconds( 30 ) };
        _configurations = new ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>>( StringComparer.OrdinalIgnoreCase );
        _pending = new ConcurrentDictionary<string, PendingLogin>( StringComparer.Ordinal );
    }

    /// <summary>
    /// Gets the number of pending logins.
    /// </summary>
    public int PendingLoginCount => _pending.Count;

    /// <summary>
    /// Starts a login: creates the pending login and returns the authorization URL to which the caller must navigate.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="scheme">The scheme.</param>
    /// <param name="callbackUrl">The callback URL of the endpoint: it must be one of the <see cref="OidcSchemeOptions.CallbackUrls"/>.</param>
    /// <param name="correlationHash">The hash of the correlation secret of the endpoint.</param>
    /// <param name="rememberMe">Whether the session will be remembered.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The authorization URL, or the error.</returns>
    public async Task<(string? Url, string? Error)> StartAsync( IActivityMonitor monitor,
                                                                OidcSchemeOptions scheme,
                                                                string callbackUrl,
                                                                string correlationHash,
                                                                bool rememberMe,
                                                                DateTime utcNow )
    {
        Throw.CheckNotNullArgument( scheme );
        Throw.CheckNotNullOrEmptyArgument( correlationHash );
        if( !scheme.CallbackUrls.Contains( callbackUrl, StringComparer.Ordinal ) )
        {
            return (null, $"The callback '{callbackUrl}' is not allowed for the scheme '{scheme.Scheme}'.");
        }
        PurgeExpired( utcNow );
        if( _pending.Count >= MaxPendingLogins )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Too many pending logins ({_pending.Count}): '{scheme.Scheme}' login refused." );
            return (null, "Too many logins in progress. Please retry later.");
        }
        var configuration = await GetConfigurationAsync( monitor, scheme ).ConfigureAwait( false );
        if( configuration == null ) return (null, $"The provider of the scheme '{scheme.Scheme}' is not available.");

        var state = NewRandom();
        var nonce = NewRandom();
        var verifier = NewRandom();
        var challenge = Base64Url.EncodeToString( SHA256.HashData( Encoding.ASCII.GetBytes( verifier ) ) );
        _pending[state] = new PendingLogin( scheme, callbackUrl, correlationHash, nonce, verifier, rememberMe, utcNow + PendingLoginLifetime );

        var endpoint = configuration.AuthorizationEndpoint;
        var url = new StringBuilder( endpoint ).Append( endpoint.Contains( '?' ) ? '&' : '?' )
                    .Append( "response_type=code" )
                    .Append( "&client_id=" ).Append( Uri.EscapeDataString( scheme.ClientId ) )
                    .Append( "&redirect_uri=" ).Append( Uri.EscapeDataString( callbackUrl ) )
                    .Append( "&scope=" ).Append( Uri.EscapeDataString( scheme.Scopes ) )
                    .Append( "&state=" ).Append( state )
                    .Append( "&nonce=" ).Append( nonce )
                    .Append( "&code_challenge=" ).Append( challenge )
                    .Append( "&code_challenge_method=S256" )
                    .ToString();
        monitor.Info( $"'{scheme.Scheme}' login started." );
        return (url, null);
    }

    /// <summary>
    /// Completes a login: consumes the pending login, checks the correlation, exchanges the code and validates the
    /// identity token.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="state">The state sent back by the provider.</param>
    /// <param name="code">The authorization code.</param>
    /// <param name="error">The error sent back by the provider, if any.</param>
    /// <param name="presentedCorrelationHash">The hash of the correlation secret presented by the caller.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The completion.</returns>
    public async Task<Completion> CompleteAsync( IActivityMonitor monitor,
                                                 string state,
                                                 string code,
                                                 string? error,
                                                 string? presentedCorrelationHash,
                                                 DateTime utcNow )
    {
        if( string.IsNullOrEmpty( state ) || !_pending.TryRemove( state, out var p ) )
        {
            return Failure( monitor, null, "This login is unknown or has expired.", "Authentication.RemoteLoginExpired" );
        }
        if( p.Expires < utcNow )
        {
            return Failure( monitor, p.Scheme, "This login has expired.", "Authentication.RemoteLoginExpired" );
        }
        if( presentedCorrelationHash == null
            || !CryptographicOperations.FixedTimeEquals( Encoding.ASCII.GetBytes( presentedCorrelationHash ), Encoding.ASCII.GetBytes( p.CorrelationHash ) ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{p.Scheme.Scheme}' login completed by a caller that didn't start it." );
            return Failure( monitor, p.Scheme, "This login has not been started here.", "Authentication.RemoteLoginCorrelation" );
        }
        if( error != null )
        {
            return Failure( monitor, p.Scheme, $"The provider refused the login ({error}).", "Authentication.RemoteLoginRefused" );
        }
        if( string.IsNullOrEmpty( code ) )
        {
            return Failure( monitor, p.Scheme, "The provider sent no authorization code.", "Authentication.RemoteLoginFailed" );
        }
        var configuration = await GetConfigurationAsync( monitor, p.Scheme ).ConfigureAwait( false );
        if( configuration == null )
        {
            return Failure( monitor, p.Scheme, $"The provider of the scheme '{p.Scheme.Scheme}' is not available.", "Authentication.RemoteLoginFailed" );
        }
        var idToken = await RedeemCodeAsync( monitor, configuration, p, code ).ConfigureAwait( false );
        if( idToken == null )
        {
            return Failure( monitor, p.Scheme, "The authorization code cannot be redeemed.", "Authentication.RemoteLoginFailed" );
        }
        var sub = await ValidateIdTokenAsync( monitor, p, configuration, idToken ).ConfigureAwait( false );
        if( sub == null )
        {
            return Failure( monitor, p.Scheme, "The identity token is invalid.", "Authentication.RemoteLoginFailed" );
        }
        monitor.Info( $"'{p.Scheme.Scheme}' login completed." );
        return new Completion( p.Scheme, sub, p.RememberMe, null, null );
    }

    static Completion Failure( IActivityMonitor monitor, OidcSchemeOptions? scheme, string text, string resName )
    {
        monitor.Warn( $"Remote login{(scheme != null ? $" '{scheme.Scheme}'" : "")} failed: {text}" );
        return new Completion( scheme, null, false, text, resName );
    }

    async Task<string?> RedeemCodeAsync( IActivityMonitor monitor, OpenIdConnectConfiguration configuration, PendingLogin p, string code )
    {
        try
        {
            using var content = new FormUrlEncodedContent( new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = p.CallbackUrl,
                ["client_id"] = p.Scheme.ClientId,
                ["client_secret"] = p.Scheme.ClientSecret,
                ["code_verifier"] = p.CodeVerifier
            } );
            using var response = await _http.PostAsync( configuration.TokenEndpoint, content ).ConfigureAwait( false );
            var body = await response.Content.ReadAsStringAsync().ConfigureAwait( false );
            if( !response.IsSuccessStatusCode )
            {
                // The body of an error response describes the error (it holds no token).
                monitor.Warn( $"Token endpoint of '{p.Scheme.Scheme}' answered {(int)response.StatusCode}: {body}" );
                return null;
            }
            using var json = JsonDocument.Parse( body );
            if( json.RootElement.TryGetProperty( "id_token", out var idToken ) && idToken.ValueKind == JsonValueKind.String )
            {
                return idToken.GetString();
            }
            monitor.Warn( $"Token endpoint of '{p.Scheme.Scheme}' returned no id_token." );
            return null;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While redeeming the code of a '{p.Scheme.Scheme}' login.", ex );
            return null;
        }
    }

    async Task<string?> ValidateIdTokenAsync( IActivityMonitor monitor, PendingLogin p, OpenIdConnectConfiguration configuration, string idToken )
    {
        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync( idToken, CreateParameters( p.Scheme, configuration ) ).ConfigureAwait( false );
        if( !result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException )
        {
            // The provider may have rotated its keys: reads its configuration again (once).
            var manager = _configurations[p.Scheme.Scheme];
            manager.RequestRefresh();
            var refreshed = await GetConfigurationAsync( monitor, p.Scheme ).ConfigureAwait( false );
            if( refreshed != null ) result = await handler.ValidateTokenAsync( idToken, CreateParameters( p.Scheme, refreshed ) ).ConfigureAwait( false );
        }
        if( !result.IsValid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Invalid identity token for a '{p.Scheme.Scheme}' login.", result.Exception );
            return null;
        }
        if( !result.Claims.TryGetValue( "nonce", out var nonce ) || nonce is not string n || n != p.Nonce )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Invalid nonce in the identity token of a '{p.Scheme.Scheme}' login." );
            return null;
        }
        if( !result.Claims.TryGetValue( "sub", out var sub ) || sub is not string s || s.Length == 0 )
        {
            monitor.Warn( $"No subject in the identity token of a '{p.Scheme.Scheme}' login." );
            return null;
        }
        return s;
    }

    static TokenValidationParameters CreateParameters( OidcSchemeOptions scheme, OpenIdConnectConfiguration configuration )
    {
        return new TokenValidationParameters
        {
            ValidIssuer = scheme.Issuer,
            ValidAudience = scheme.ClientId,
            IssuerSigningKeys = configuration.SigningKeys,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes( 2 )
        };
    }

    async Task<OpenIdConnectConfiguration?> GetConfigurationAsync( IActivityMonitor monitor, OidcSchemeOptions scheme )
    {
        var manager = _configurations.GetOrAdd( scheme.Scheme, _ =>
        {
            var metadata = scheme.Authority.ToString().TrimEnd( '/' ) + "/.well-known/openid-configuration";
            var retriever = new HttpDocumentRetriever( _http ) { RequireHttps = !scheme.Authority.IsLoopback };
            return new ConfigurationManager<OpenIdConnectConfiguration>( metadata, new OpenIdConnectConfigurationRetriever(), retriever );
        } );
        try
        {
            var configuration = await manager.GetConfigurationAsync().ConfigureAwait( false );
            if( configuration.Issuer != scheme.Issuer )
            {
                monitor.Error( $"The provider of '{scheme.Scheme}' announces the issuer '{configuration.Issuer}', '{scheme.Issuer}' is expected." );
                return null;
            }
            return configuration;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While reading the configuration of the provider of '{scheme.Scheme}'.", ex );
            return null;
        }
    }

    void PurgeExpired( DateTime utcNow )
    {
        foreach( var (state, p) in _pending )
        {
            if( p.Expires < utcNow ) _pending.TryRemove( state, out _ );
        }
    }

    static string NewRandom() => Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 32 ) );
}
