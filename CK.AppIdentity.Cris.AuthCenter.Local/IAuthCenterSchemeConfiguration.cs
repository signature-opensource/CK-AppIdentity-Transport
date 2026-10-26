using CK.Core;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Declares the configuration sub-section of a scheme family package ("Oidc" for the "AuthCenter:Oidc" section).
/// The core of the Authentication Center refuses a sub-section of its "AuthCenter" configuration that no installed
/// package declares: a configured family that silently does nothing (its package is missing) is a misconfiguration.
/// <para>
/// This is a declaration only, distinct from the family's feature driver (that depends on the AuthCenter's one): the
/// <see cref="AuthCenterFeatureDriver"/> knows the declared keys when it reads its configuration.
/// </para>
/// </summary>
[IsMultiple]
public interface IAuthCenterSchemeConfiguration : ISingletonAutoService
{
    /// <summary>
    /// Gets the key of the configuration sub-section of the family ("Oidc").
    /// </summary>
    string ConfigurationKey { get; }
}
