namespace CK.AppIdentity.Cris.AuthCenter.Passkey;

/// <summary>
/// Declares the "AuthCenter:Passkey" configuration section (see <see cref="IAuthCenterSchemeConfiguration"/>).
/// </summary>
public sealed class AuthCenterPasskeyConfiguration : IAuthCenterSchemeConfiguration
{
    /// <summary>
    /// The key of the configuration sub-section: "Passkey".
    /// </summary>
    public const string Key = "Passkey";

    /// <inheritdoc />
    public string ConfigurationKey => Key;
}
