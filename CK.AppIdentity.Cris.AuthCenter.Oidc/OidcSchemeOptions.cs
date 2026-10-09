using CK.Core;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;

namespace CK.AppIdentity.Cris.AuthCenter.Oidc;

/// <summary>
/// The settings of an OpenID Connect scheme of a local Authentication Center, read from its "AuthCenter:Oidc:&lt;Suffix&gt;"
/// configuration section. The scheme is "Oidc.&lt;Suffix&gt;": the login uses the "Oidc" login provider with the
/// <c>SchemeSuffix</c> and the <c>Sub</c> of the identity (the payload of CK.DB.User.UserOidc for instance).
/// <para>
/// A scheme accepts a single issuer: <c>sub</c> is unique per issuer only, and the identity of an actor is
/// (scheme, sub). Multi-tenant endpoints (whose issuer varies) are not supported.
/// </para>
/// </summary>
public sealed partial class OidcSchemeOptions
{
    OidcSchemeOptions( string suffix,
                       Uri authority,
                       string issuer,
                       string clientId,
                       string clientSecret,
                       string? tokenEndpointAuthMethod,
                       string scopes,
                       ImmutableArray<string> callbackUrls,
                       bool getClaimsFromUserInfoEndpoint,
                       ImmutableArray<string> excludedClaims,
                       bool allowAccountCreation )
    {
        Suffix = suffix;
        Authority = authority;
        Issuer = issuer;
        ClientId = clientId;
        ClientSecret = clientSecret;
        TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        Scopes = scopes;
        CallbackUrls = callbackUrls;
        GetClaimsFromUserInfoEndpoint = getClaimsFromUserInfoEndpoint;
        ExcludedClaims = excludedClaims;
        AllowAccountCreation = allowAccountCreation;
    }

    /// <summary>
    /// Gets the scheme suffix (the configuration key): letters and digits, not starting with "Oidc".
    /// </summary>
    public string Suffix { get; }

    /// <summary>
    /// Gets the scheme: "Oidc.<see cref="Suffix"/>".
    /// </summary>
    public string Scheme => "Oidc." + Suffix;

    /// <summary>
    /// Gets the authority: the discovery document is "<c>&lt;Authority&gt;/.well-known/openid-configuration</c>".
    /// It must be https (http is accepted on a loopback address, for the development and the tests).
    /// </summary>
    public Uri Authority { get; }

    /// <summary>
    /// Gets the issuer: the "iss" of the identity tokens must be exactly this one (and the discovery document must
    /// announce it). Defaults to the <see cref="Authority"/> (without trailing '/').
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// Gets the client identifier at the provider (the expected audience of the identity tokens).
    /// </summary>
    public string ClientId { get; }

    /// <summary>
    /// Gets the client secret at the provider. Only the Authentication Center knows it.
    /// </summary>
    public string ClientSecret { get; }

    /// <summary>
    /// The <see cref="TokenEndpointAuthMethod"/> that sends the client secret in an HTTP Basic Authorization header (RFC 6749
    /// section 2.3.1): the default of OpenID Connect.
    /// </summary>
    public const string ClientSecretBasic = "client_secret_basic";

    /// <summary>
    /// The <see cref="TokenEndpointAuthMethod"/> that sends the client secret in the body of the token request.
    /// </summary>
    public const string ClientSecretPost = "client_secret_post";

    /// <summary>
    /// Gets how the client authenticates at the token endpoint: <see cref="ClientSecretBasic"/> or <see cref="ClientSecretPost"/>.
    /// When null (the default), it is chosen from the <c>token_endpoint_auth_methods_supported</c> of the discovery
    /// document: <see cref="ClientSecretBasic"/> (the default of the specification when the provider announces nothing),
    /// <see cref="ClientSecretPost"/> only when the provider announces it and not the basic one.
    /// </summary>
    public string? TokenEndpointAuthMethod { get; }

    /// <summary>
    /// Gets the requested scopes (space separated, "openid" is always included). Defaults to "openid".
    /// </summary>
    public string Scopes { get; }

    /// <summary>
    /// Gets the callback URLs (the redirect URIs registered at the provider) of the endpoints that can start a login
    /// with this scheme: a login started by an endpoint whose callback is not one of them is refused.
    /// </summary>
    public ImmutableArray<string> CallbackUrls { get; }

    /// <summary>
    /// Gets whether the claims are completed by the UserInfo endpoint of the provider, with the access token, after the
    /// code exchange (an explicit extra HTTP call per login). Some providers send the profile, email and phone claims
    /// from this endpoint only. The UserInfo <c>sub</c> must be the one of the identity token. Defaults to false.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; }

    /// <summary>
    /// Gets the claims that the application must not keep (exact names: personal data it doesn't want, large claims
    /// like Entra's "groups"). The protocol claims and "sub" are never kept. Empty by default.
    /// </summary>
    public ImmutableArray<string> ExcludedClaims { get; }

    /// <summary>
    /// Gets whether an identity bound to no actor may create an account (through the application's
    /// <see cref="IAutoCreateAccountService"/>, that keeps its own conditions). Defaults to false.
    /// </summary>
    public bool AllowAccountCreation { get; }

    [GeneratedRegex( "^[A-Za-z0-9]+$" )]
    private static partial Regex SuffixRegex();

    internal static bool IsAllowedUri( Uri u ) => u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback);

    internal static ImmutableArray<OidcSchemeOptions>? Read( IActivityMonitor monitor, ImmutableConfigurationSection? section )
    {
        if( section == null ) return ImmutableArray<OidcSchemeOptions>.Empty;
        bool success = true;
        var result = ImmutableArray.CreateBuilder<OidcSchemeOptions>();
        foreach( var s in section.GetChildren() )
        {
            var o = ReadOne( monitor, s );
            if( o == null ) success = false;
            else result.Add( o );
        }
        return success ? result.ToImmutable() : null;
    }

    static OidcSchemeOptions? ReadOne( IActivityMonitor monitor, ImmutableConfigurationSection s )
    {
        bool success = true;
        void Error( string text )
        {
            monitor.Error( $"Invalid '{s.Path}': {text}" );
            success = false;
        }
        var suffix = s.Key;
        if( !SuffixRegex().IsMatch( suffix ) || suffix.StartsWith( "Oidc", StringComparison.OrdinalIgnoreCase ) )
        {
            Error( "the scheme suffix must be letters and digits and must not start with 'Oidc'." );
        }
        Uri? authority = null;
        if( !Uri.TryCreate( s["Authority"], UriKind.Absolute, out authority ) || !IsAllowedUri( authority ) )
        {
            Error( "'Authority' must be an absolute https URL (http only on a loopback address)." );
        }
        var issuer = s["Issuer"] ?? authority?.ToString().TrimEnd( '/' );
        var clientId = s["ClientId"];
        if( string.IsNullOrWhiteSpace( clientId ) ) Error( "'ClientId' is required." );
        var clientSecret = s["ClientSecret"];
        if( string.IsNullOrWhiteSpace( clientSecret ) ) Error( "'ClientSecret' is required." );
        var authMethod = s["TokenEndpointAuthMethod"];
        if( authMethod != null && authMethod != ClientSecretBasic && authMethod != ClientSecretPost )
        {
            Error( $"'TokenEndpointAuthMethod' must be '{ClientSecretBasic}' or '{ClientSecretPost}' (or absent: it is chosen from the discovery document)." );
        }
        var scopes = (s["Scopes"] ?? "openid").Split( ' ', StringSplitOptions.RemoveEmptyEntries ).ToList();
        if( !scopes.Contains( "openid" ) ) scopes.Insert( 0, "openid" );
        var callbacks = ReadStrings( s.TryGetSection( "CallbackUrls" ) );
        if( callbacks.Count == 0 ) Error( "'CallbackUrls' is required (the redirect URIs registered at the provider)." );
        foreach( var c in callbacks )
        {
            if( !Uri.TryCreate( c, UriKind.Absolute, out var u ) || !IsAllowedUri( u ) || u.Query.Length > 0 || u.Fragment.Length > 0 )
            {
                Error( $"callback URL '{c}' must be an absolute https URL (http only on a loopback address) without query nor fragment." );
            }
        }
        var userInfo = ReadBool( s, nameof( GetClaimsFromUserInfoEndpoint ), Error );
        var excluded = ReadStrings( s.TryGetSection( nameof( ExcludedClaims ) ) );
        var allowAccountCreation = ReadBool( s, nameof( AllowAccountCreation ), Error );
        if( !success ) return null;
        return new OidcSchemeOptions( suffix,
                                      authority!,
                                      issuer!,
                                      clientId!,
                                      clientSecret!,
                                      authMethod,
                                      string.Join( ' ', scopes ),
                                      callbacks.ToImmutableArray(),
                                      userInfo,
                                      excluded.ToImmutableArray(),
                                      allowAccountCreation );
    }

    static bool ReadBool( ImmutableConfigurationSection s, string key, Action<string> error )
    {
        var v = s[key];
        if( v == null ) return false;
        if( bool.TryParse( v, out var b ) ) return b;
        error( $"'{key}' must be true or false." );
        return false;
    }

    // A list ("CallbackUrls:0", "CallbackUrls:1"...) or a comma separated value.
    static List<string> ReadStrings( ImmutableConfigurationSection? s )
    {
        if( s == null ) return [];
        if( s.HasChildren ) return s.GetChildren().Select( c => c.Value ).Where( v => !string.IsNullOrWhiteSpace( v ) ).Select( v => v!.Trim() ).ToList();
        return (s.Value ?? "").Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries ).ToList();
    }
}
