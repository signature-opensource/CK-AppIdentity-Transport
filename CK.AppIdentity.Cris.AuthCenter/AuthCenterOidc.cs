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
using System.IdentityModel.Tokens.Jwt;
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
/// The protocol is the one of Microsoft.IdentityModel (the library of the ASP.NET OpenID Connect handler): the messages
/// (<see cref="OpenIdConnectMessage"/>), the discovery and the keys (<see cref="ConfigurationManager{T}"/>), the token validation
/// (<see cref="JsonWebTokenHandler"/>) and the protocol rules (<see cref="OpenIdConnectProtocolValidator"/>: nonce, at_hash,
/// required claims). What is specific here is the pending login (state, PKCE verifier, correlation) and the HTTP call to the
/// token endpoint: the ASP.NET handler is bound to an HTTP request, the AuthCenter receives Cris commands.
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
    readonly OpenIdConnectProtocolValidator _validator;

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
        // The state is checked by the pending logins (one use). The nonce lives as long as a pending login.
        _validator = new OpenIdConnectProtocolValidator { RequireStateValidation = false, NonceLifetime = PendingLoginLifetime };
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
        // The nonce of the protocol validator (it holds its creation time: its lifetime is checked).
        var nonce = _validator.GenerateNonce();
        var verifier = NewRandom();
        var challenge = Base64Url.EncodeToString( SHA256.HashData( Encoding.ASCII.GetBytes( verifier ) ) );
        _pending[state] = new PendingLogin( scheme, callbackUrl, correlationHash, nonce, verifier, rememberMe, utcNow + PendingLoginLifetime );

        var request = new OpenIdConnectMessage
        {
            IssuerAddress = configuration.AuthorizationEndpoint,
            ClientId = scheme.ClientId,
            RedirectUri = callbackUrl,
            ResponseType = OpenIdConnectResponseType.Code,
            Scope = scheme.Scopes,
            State = state,
            Nonce = nonce
        };
        request.SetParameter( "code_challenge", challenge );
        request.SetParameter( "code_challenge_method", "S256" );
        var url = request.CreateAuthenticationRequestUrl();
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
        var tokenResponse = await RedeemCodeAsync( monitor, configuration, p, code ).ConfigureAwait( false );
        if( tokenResponse == null )
        {
            return Failure( monitor, p.Scheme, "The authorization code cannot be redeemed.", "Authentication.RemoteLoginFailed" );
        }
        var sub = await ValidateTokenResponseAsync( monitor, p, configuration, tokenResponse ).ConfigureAwait( false );
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

    async Task<OpenIdConnectMessage?> RedeemCodeAsync( IActivityMonitor monitor, OpenIdConnectConfiguration configuration, PendingLogin p, string code )
    {
        try
        {
            var request = new OpenIdConnectMessage
            {
                GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
                Code = code,
                RedirectUri = p.CallbackUrl,
                ClientId = p.Scheme.ClientId,
                ClientSecret = p.Scheme.ClientSecret
            };
            request.SetParameter( "code_verifier", p.CodeVerifier );
            using var content = new FormUrlEncodedContent( request.Parameters );
            using var response = await _http.PostAsync( configuration.TokenEndpoint, content ).ConfigureAwait( false );
            var body = await response.Content.ReadAsStringAsync().ConfigureAwait( false );
            if( !response.IsSuccessStatusCode )
            {
                // The body of an error response describes the error (it holds no token).
                monitor.Warn( $"Token endpoint of '{p.Scheme.Scheme}' answered {(int)response.StatusCode}: {body}" );
                return null;
            }
            var tokenResponse = new OpenIdConnectMessage( body );
            if( string.IsNullOrEmpty( tokenResponse.IdToken ) )
            {
                monitor.Warn( $"Token endpoint of '{p.Scheme.Scheme}' returned no id_token." );
                return null;
            }
            return tokenResponse;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While redeeming the code of a '{p.Scheme.Scheme}' login.", ex );
            return null;
        }
    }

    // The token: its signature, issuer, audience and lifetime (JsonWebTokenHandler). Then the protocol rules
    // (OpenIdConnectProtocolValidator): the required claims, the nonce, the at_hash when there is an access token.
    async Task<string?> ValidateTokenResponseAsync( IActivityMonitor monitor, PendingLogin p, OpenIdConnectConfiguration configuration, OpenIdConnectMessage tokenResponse )
    {
        var idToken = tokenResponse.IdToken;
        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync( idToken, CreateParameters( p.Scheme, configuration ) ).ConfigureAwait( false );
        if( !result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException )
        {
            // The provider may have rotated its keys: reads its configuration again (once).
            _configurations[p.Scheme.Scheme].RequestRefresh();
            var refreshed = await GetConfigurationAsync( monitor, p.Scheme ).ConfigureAwait( false );
            if( refreshed != null ) result = await handler.ValidateTokenAsync( idToken, CreateParameters( p.Scheme, refreshed ) ).ConfigureAwait( false );
        }
        if( !result.IsValid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Invalid identity token for a '{p.Scheme.Scheme}' login.", result.Exception );
            return null;
        }
        try
        {
            _validator.ValidateTokenResponse( new OpenIdConnectProtocolValidationContext
            {
                ClientId = p.Scheme.ClientId,
                Nonce = p.Nonce,
                ProtocolMessage = tokenResponse,
                ValidatedIdToken = new JwtSecurityToken( idToken )
            } );
        }
        catch( Exception ex )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The identity token of a '{p.Scheme.Scheme}' login breaks the protocol.", ex );
            return null;
        }
        return result.Claims.TryGetValue( "sub", out var sub ) && sub is string s && s.Length > 0 ? s : null;
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
