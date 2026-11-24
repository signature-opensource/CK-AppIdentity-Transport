using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.AuthCenter.Password;

/// <summary>
/// The scheme family of the "Password" option (see <see cref="AuthCenterPasswordOption"/>): one scheme, "Basic" (a user
/// name and a password), whose provider has the same name. It never creates an account: an account is created by the
/// administration, not by a login.
/// </summary>
public sealed class AuthCenterPassword : IAuthCenterScheme
{
    /// <inheritdoc />
    public string ProviderName => AuthCenterPasswordOption.Scheme;

    /// <inheritdoc />
    public IEnumerable<string> Schemes => [AuthCenterPasswordOption.Scheme];

    /// <inheritdoc />
    public bool AllowsAccountCreation( string scheme ) => false;
}
