using CK.Core;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace CK.AppIdentity.AuthCenter.Oidc;

/// <summary>
/// The "Oidc" option of the Authentication Center: the OpenID Connect scheme family (<see cref="AuthCenterOidc"/>) of every
/// local Authentication Center, the dynamic tenants included, with the schemes of its configuration
/// (<see cref="AuthCenterOidcOptionConfiguration"/>: possibly none, the family then hides the "Oidc" provider name in the
/// scheme listing). The client secrets are secrets: their configuration should be a handle (<c>{ "$SECRET": "&lt;Name&gt;" }</c>).
/// <code>
/// "AuthCenter": {
///   "Oidc": {
///     "Schemes": {
///       "Google": { "Authority": "https://accounts.google.com", "ClientId": "...", "ClientSecret": { "$SECRET": "Google:ClientSecret" } }
///     }
///   }
/// }
/// </code>
/// </summary>
[PartyFeatureOption( "Oidc", TypeActivation.ByDefault )]
[Configuration<AuthCenterOidcOptionConfiguration>]
[ConfigurationSecret( "Party:Schemes:*:ClientSecret" )]
public sealed class AuthCenterOidcOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    readonly AuthCenterOidcHttpClient _http;
    readonly IEnumerable<ILoginProvider> _providers;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterOidcOption"/>.
    /// </summary>
    /// <param name="configuration">The configuration of the option: its schemes.</param>
    /// <param name="http">The HTTP client of the application.</param>
    /// <param name="providers">The login providers: the "Oidc" one completes the logins (its payload is an <see cref="IOidcLoginPayload"/>).</param>
    public AuthCenterOidcOption( AuthCenterOidcOptionConfiguration configuration, AuthCenterOidcHttpClient http, IEnumerable<ILoginProvider> providers )
    {
        _http = http;
        _providers = providers;
        Schemes = OidcSchemeOptions.Create( configuration );
    }

    /// <summary>
    /// Gets the schemes.
    /// </summary>
    public ImmutableArray<OidcSchemeOptions> Schemes { get; }

    /// <inheritdoc />
    public IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local ) => new AuthCenterOidc( Schemes, _http.Client, _providers );
}
