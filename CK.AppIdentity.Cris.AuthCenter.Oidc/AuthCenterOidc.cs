using CK.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter.Oidc;

/// <summary>
/// The OpenID Connect client of a <see cref="LocalAuthCenter"/> (authorization code flow with PKCE): the
/// <see cref="IAuthCenterRemoteScheme"/> family of the "Oidc.&lt;Suffix&gt;" schemes. It alone holds the client secrets:
/// its remotes' endpoints only execute the start of a login and the callback (their operations are handled here).
/// <list type="number">
///   <item>
///   <see cref="StartAsync"/> generates the nonce and the PKCE verifier (kept with the pending login by the core) and
///   returns the authorization URL.
///   </item>
///   <item>
///   <see cref="CompleteAsync"/> exchanges the code and validates the identity token (signature, issuer, audience,
///   lifetime, nonce), then fills the payload of the "Oidc" <see cref="ILoginProvider"/>: its writable string
///   properties <c>SchemeSuffix</c> and <c>Sub</c> (the payload of CK.DB.User.UserOidc for instance).
///   </item>
/// </list>
/// The protocol is the one of Microsoft.IdentityModel (the library of the ASP.NET OpenID Connect handler): the messages
/// (<see cref="OpenIdConnectMessage"/>), the discovery and the keys (<see cref="ConfigurationManager{T}"/>), the token validation
/// (<see cref="JsonWebTokenHandler"/>) and the protocol rules (<see cref="OpenIdConnectProtocolValidator"/>: nonce, at_hash,
/// required claims). What is specific here is the HTTP call to the token endpoint: the ASP.NET handler is bound to an HTTP
/// request, the AuthCenter receives Cris commands.
/// </summary>
public sealed class AuthCenterOidc : IAuthCenterRemoteScheme
{
    /// <summary>
    /// The "Oidc" provider name.
    /// </summary>
    public const string OidcProviderName = "Oidc";

    readonly ImmutableArray<OidcSchemeOptions> _schemes;
    readonly HttpClient _http;
    readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _configurations;
    readonly OpenIdConnectProtocolValidator _validator;

    // The private data of a pending login.
    sealed record PendingData( OidcSchemeOptions Scheme, string Nonce, string CodeVerifier );

    internal AuthCenterOidc( ImmutableArray<OidcSchemeOptions> schemes )
    {
        _schemes = schemes;
        _http = new HttpClient() { Timeout = TimeSpan.FromSeconds( 30 ) };
        _configurations = new ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>>( StringComparer.OrdinalIgnoreCase );
        // The state is checked by the core (the pending logins). The nonce lives as long as a pending login.
        _validator = new OpenIdConnectProtocolValidator { RequireStateValidation = false, NonceLifetime = LocalAuthCenter.PendingRemoteLoginLifetime };
    }

    /// <summary>
    /// Gets the configured OpenID Connect schemes ("Oidc:&lt;Suffix&gt;" sections).
    /// </summary>
    public ImmutableArray<OidcSchemeOptions> SchemeOptions => _schemes;

    /// <summary>
    /// Finds the options of a scheme.
    /// </summary>
    /// <param name="scheme">The scheme ("Oidc.Google" for instance).</param>
    /// <returns>The options or null.</returns>
    public OidcSchemeOptions? FindScheme( string scheme ) => _schemes.FirstOrDefault( o => string.Equals( o.Scheme, scheme, StringComparison.OrdinalIgnoreCase ) );

    /// <inheritdoc />
    public string ProviderName => OidcProviderName;

    /// <inheritdoc />
    public IEnumerable<string> Schemes => _schemes.Select( o => o.Scheme );

    /// <inheritdoc />
    public bool AllowsAccountCreation( string scheme ) => FindScheme( scheme )?.AllowAccountCreation is true;

    /// <summary>
    /// The claims that are never kept: the protocol claims (Microsoft's defaults) and "sub" (the identity itself).
    /// </summary>
    public static readonly ImmutableHashSet<string> ProtocolClaims = ImmutableHashSet.Create( StringComparer.Ordinal,
        "iss", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash", "auth_time", "azp", "sid", "amr", "acr", "sub" );

    /// <inheritdoc />
    public bool IsAllowedCallback( string scheme, string callbackUrl )
    {
        return FindScheme( scheme )?.CallbackUrls.Contains( callbackUrl, StringComparer.Ordinal ) is true;
    }

    /// <inheritdoc />
    public async Task<RemoteLoginStart> StartAsync( IActivityMonitor monitor, string scheme, string state, string callbackUrl )
    {
        var options = FindScheme( scheme );
        if( options == null || !options.CallbackUrls.Contains( callbackUrl, StringComparer.Ordinal ) )
        {
            return new RemoteLoginStart( null, null, $"The callback '{callbackUrl}' is not allowed for the scheme '{scheme}'." );
        }
        var configuration = await GetConfigurationAsync( monitor, options ).ConfigureAwait( false );
        if( configuration == null ) return new RemoteLoginStart( null, null, $"The provider of the scheme '{options.Scheme}' is not available." );
        if( GetTokenEndpointAuthMethod( monitor, options, configuration ) == null )
        {
            return new RemoteLoginStart( null, null, $"The provider of the scheme '{options.Scheme}' does not accept a client secret." );
        }

        // The nonce of the protocol validator (it holds its creation time: its lifetime is checked).
        var nonce = _validator.GenerateNonce();
        var verifier = Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 32 ) );
        var challenge = Base64Url.EncodeToString( SHA256.HashData( Encoding.ASCII.GetBytes( verifier ) ) );

        var request = new OpenIdConnectMessage
        {
            IssuerAddress = configuration.AuthorizationEndpoint,
            ClientId = options.ClientId,
            RedirectUri = callbackUrl,
            ResponseType = OpenIdConnectResponseType.Code,
            Scope = options.Scopes,
            State = state,
            Nonce = nonce
        };
        request.SetParameter( "code_challenge", challenge );
        request.SetParameter( "code_challenge_method", "S256" );
        var url = request.CreateAuthenticationRequestUrl();
        monitor.Info( $"'{options.Scheme}' login started." );
        return new RemoteLoginStart( url, new PendingData( options, nonce, verifier ), null );
    }

    /// <inheritdoc />
    public async Task<RemoteLoginCompletion> CompleteAsync( IActivityMonitor monitor,
                                                            PendingRemoteLogin pending,
                                                            string? code,
                                                            string? error,
                                                            ILoginProvider provider )
    {
        var p = (PendingData)pending.SchemeData!;
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
        var tokenResponse = await RedeemCodeAsync( monitor, configuration, p, pending.CallbackUrl, code ).ConfigureAwait( false );
        if( tokenResponse == null )
        {
            return Failure( monitor, p.Scheme, "The authorization code cannot be redeemed.", "Authentication.RemoteLoginFailed" );
        }
        var sub = await ValidateTokenResponseAsync( monitor, p, configuration, tokenResponse ).ConfigureAwait( false );
        if( sub == null )
        {
            return Failure( monitor, p.Scheme, "The identity token is invalid.", "Authentication.RemoteLoginFailed" );
        }
        var claims = await GetClaimsAsync( monitor, p.Scheme, configuration, tokenResponse, sub ).ConfigureAwait( false );
        if( claims == null )
        {
            return Failure( monitor, p.Scheme, "The claims of the provider cannot be read.", "Authentication.RemoteLoginFailed" );
        }
        var payload = provider.CreatePayload( p.Scheme.Scheme );
        if( !TrySet( payload, "SchemeSuffix", p.Scheme.Suffix ) || !TrySet( payload, "Sub", sub ) )
        {
            return Failure( monitor, p.Scheme, $"The payload of the '{OidcProviderName}' login provider ('{payload.GetType():N}') has no writable SchemeSuffix and Sub.", "Authentication.InvalidPayload" );
        }
        // The claims are kept when the provider's payload can hold them.
        if( !TrySet( payload, "Claims", claims ) )
        {
            monitor.Trace( $"The payload of the '{OidcProviderName}' login provider ('{payload.GetType():N}') has no writable Claims: they are not kept." );
        }
        monitor.Info( $"'{p.Scheme.Scheme}' login completed." );
        return new RemoteLoginCompletion( payload, null, null );
    }

    // The claims of the validated identity token, completed by the UserInfo endpoint when configured (its "sub" must be
    // the identity token's), without the protocol claims nor the excluded ones, as a JSON object (the values as received).
    // On a conflict, the identity token wins: it is signed, UserInfo is not (it comes over TLS).
    async Task<string?> GetClaimsAsync( IActivityMonitor monitor, OidcSchemeOptions scheme, OpenIdConnectConfiguration configuration, OpenIdConnectMessage tokenResponse, string sub )
    {
        var claims = new JsonObject();
        if( scheme.GetClaimsFromUserInfoEndpoint )
        {
            var userInfo = await GetUserInfoAsync( monitor, scheme, configuration, tokenResponse.AccessToken ).ConfigureAwait( false );
            if( userInfo == null ) return null;
            if( userInfo["sub"] is not JsonValue v || v.GetValueKind() != JsonValueKind.String || v.GetValue<string>() != sub )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The UserInfo of a '{scheme.Scheme}' login is not about the subject of the identity token." );
                return null;
            }
            CopyClaims( scheme, userInfo, claims );
        }
        var idToken = new JsonWebToken( tokenResponse.IdToken );
        if( JsonNode.Parse( Base64Url.DecodeFromChars( idToken.EncodedPayload ) ) is not JsonObject idClaims ) return null;
        CopyClaims( scheme, idClaims, claims );
        return claims.ToJsonString();
    }

    static void CopyClaims( OidcSchemeOptions scheme, JsonObject source, JsonObject target )
    {
        foreach( var (name, value) in source )
        {
            if( ProtocolClaims.Contains( name ) || scheme.ExcludedClaims.Contains( name, StringComparer.Ordinal ) ) continue;
            target[name] = value?.DeepClone();
        }
    }

    async Task<JsonObject?> GetUserInfoAsync( IActivityMonitor monitor, OidcSchemeOptions scheme, OpenIdConnectConfiguration configuration, string? accessToken )
    {
        if( string.IsNullOrEmpty( configuration.UserInfoEndpoint ) )
        {
            monitor.Error( $"The provider of '{scheme.Scheme}' announces no UserInfo endpoint (GetClaimsFromUserInfoEndpoint is true)." );
            return null;
        }
        if( string.IsNullOrEmpty( accessToken ) )
        {
            monitor.Warn( $"The token endpoint of '{scheme.Scheme}' returned no access token: UserInfo cannot be called." );
            return null;
        }
        try
        {
            using var request = new HttpRequestMessage( HttpMethod.Get, configuration.UserInfoEndpoint );
            request.Headers.Authorization = new AuthenticationHeaderValue( "Bearer", accessToken );
            using var response = await _http.SendAsync( request ).ConfigureAwait( false );
            if( !response.IsSuccessStatusCode )
            {
                monitor.Warn( $"UserInfo endpoint of '{scheme.Scheme}' answered {(int)response.StatusCode}." );
                return null;
            }
            if( response.Content.Headers.ContentType?.MediaType != "application/json" )
            {
                // A signed or encrypted UserInfo response (application/jwt) is not supported.
                monitor.Warn( $"UserInfo endpoint of '{scheme.Scheme}' answered '{response.Content.Headers.ContentType?.MediaType}': application/json is expected." );
                return null;
            }
            return JsonNode.Parse( await response.Content.ReadAsStringAsync().ConfigureAwait( false ) ) as JsonObject;
        }
        catch( Exception ex )
        {
            monitor.Error( $"While reading the UserInfo of a '{scheme.Scheme}' login.", ex );
            return null;
        }
    }

    static RemoteLoginCompletion Failure( IActivityMonitor monitor, OidcSchemeOptions scheme, string text, string resName )
    {
        monitor.Warn( $"Remote login '{scheme.Scheme}' failed: {text}" );
        return RemoteLoginCompletion.Failure( text, resName );
    }

    static bool TrySet( object payload, string name, string value )
    {
        var p = payload.GetType().GetProperty( name, BindingFlags.Public | BindingFlags.Instance );
        if( p == null || p.PropertyType != typeof( string ) || !p.CanWrite ) return false;
        p.SetValue( payload, value );
        return true;
    }

    async Task<OpenIdConnectMessage?> RedeemCodeAsync( IActivityMonitor monitor, OpenIdConnectConfiguration configuration, PendingData p, string callbackUrl, string code )
    {
        try
        {
            var authMethod = GetTokenEndpointAuthMethod( monitor, p.Scheme, configuration );
            if( authMethod == null ) return null;
            var request = new OpenIdConnectMessage
            {
                GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
                Code = code,
                RedirectUri = callbackUrl,
            };
            request.SetParameter( "code_verifier", p.CodeVerifier );
            using var httpRequest = new HttpRequestMessage( HttpMethod.Post, configuration.TokenEndpoint );
            if( authMethod == OidcSchemeOptions.ClientSecretBasic )
            {
                // RFC 6749 section 2.3.1: the client id and the secret are form-url-encoded before being joined (a ':'
                // in the id or the secret is then unambiguous).
                var credentials = WebUtility.UrlEncode( p.Scheme.ClientId ) + ':' + WebUtility.UrlEncode( p.Scheme.ClientSecret );
                httpRequest.Headers.Authorization = new AuthenticationHeaderValue( "Basic", Convert.ToBase64String( Encoding.UTF8.GetBytes( credentials ) ) );
            }
            else
            {
                request.ClientId = p.Scheme.ClientId;
                request.ClientSecret = p.Scheme.ClientSecret;
            }
            httpRequest.Content = new FormUrlEncodedContent( request.Parameters );
            using var response = await _http.SendAsync( httpRequest ).ConfigureAwait( false );
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
    async Task<string?> ValidateTokenResponseAsync( IActivityMonitor monitor, PendingData p, OpenIdConnectConfiguration configuration, OpenIdConnectMessage tokenResponse )
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

    // The configured method, else the one announced by the provider: the basic one when it announces nothing (the default
    // of OpenID Connect Discovery) or when it announces it, the post one only when it announces it and not the basic one.
    // Null (with an error) when the provider announces neither: the other methods use no client secret.
    static string? GetTokenEndpointAuthMethod( IActivityMonitor monitor, OidcSchemeOptions scheme, OpenIdConnectConfiguration configuration )
    {
        if( scheme.TokenEndpointAuthMethod != null ) return scheme.TokenEndpointAuthMethod;
        var supported = configuration.TokenEndpointAuthMethodsSupported;
        if( supported.Count == 0 || supported.Contains( OidcSchemeOptions.ClientSecretBasic ) ) return OidcSchemeOptions.ClientSecretBasic;
        if( supported.Contains( OidcSchemeOptions.ClientSecretPost ) ) return OidcSchemeOptions.ClientSecretPost;
        monitor.Error( $"The provider of '{scheme.Scheme}' accepts neither '{OidcSchemeOptions.ClientSecretBasic}' nor '{OidcSchemeOptions.ClientSecretPost}' (it announces '{string.Join( "', '", supported )}')." );
        return null;
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
}
