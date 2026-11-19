using CK.Core;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace CK.AppIdentity.AuthCenter.Oidc;

/// <summary>
/// The "Oidc" option of the Authentication Center: the OpenID Connect scheme family (<see cref="AuthCenterOidc"/>) of every
/// local Authentication Center, the dynamic tenants included, with the schemes of its "AuthCenter:Oidc" section (possibly
/// none: the family then hides the "Oidc" provider name in the scheme listing). The client secrets are secrets: their
/// configuration should be a handle (<c>{ "$SECRET": "&lt;Name&gt;" }</c>).
/// <code>
/// "AuthCenter": {
///   "Oidc": {
///     "Google": { "Authority": "https://accounts.google.com", "ClientId": "...", "ClientSecret": { "$SECRET": "Google:ClientSecret" } }
///   }
/// }
/// </code>
/// </summary>
[PartyFeatureOption( "Oidc", TypeActivation.ByDefault )]
[ConfigurationSecret( "Party:*:ClientSecret" )]
public sealed class AuthCenterOidcOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    readonly AuthCenterOidcHttpClient _http;
    readonly IEnumerable<ILoginProvider> _providers;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterOidcOption"/>.
    /// </summary>
    /// <param name="configuration">The "AuthCenter:Oidc" section: a section per scheme. Null when there is none.</param>
    /// <param name="http">The HTTP client of the application.</param>
    /// <param name="providers">The login providers: the "Oidc" one completes the logins (its payload is an <see cref="IOidcLoginPayload"/>).</param>
    public AuthCenterOidcOption( IConfiguration? configuration, AuthCenterOidcHttpClient http, IEnumerable<ILoginProvider> providers )
    {
        _http = http;
        _providers = providers;
        Schemes = OidcSchemeOptions.Read( configuration );
    }

    /// <summary>
    /// Gets the schemes.
    /// </summary>
    public ImmutableArray<OidcSchemeOptions> Schemes { get; }

    /// <inheritdoc />
    public IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local ) => new AuthCenterOidc( Schemes, _http.Client, _providers );
}
