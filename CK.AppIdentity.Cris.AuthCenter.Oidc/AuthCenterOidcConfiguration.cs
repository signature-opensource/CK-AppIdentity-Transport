namespace CK.AppIdentity.Cris.AuthCenter.Oidc;

/// <summary>
/// Declares the "AuthCenter:Oidc" configuration section (see <see cref="IAuthCenterSchemeConfiguration"/>).
/// </summary>
public sealed class AuthCenterOidcConfiguration : IAuthCenterSchemeConfiguration
{
    /// <summary>
    /// The key of the configuration sub-section: "Oidc".
    /// </summary>
    public const string Key = "Oidc";

    /// <inheritdoc />
    public string ConfigurationKey => Key;
}
