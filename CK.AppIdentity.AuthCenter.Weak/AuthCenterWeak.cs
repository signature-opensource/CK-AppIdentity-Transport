using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.AuthCenter.Weak;

/// <summary>
/// The scheme family of the "Weak" option (see <see cref="AuthCenterWeakOption"/>): one scheme, "Weak" (a weak actor,
/// at most at the Unsafe level), whose provider has the same name. It never creates an account: an account is created
/// by the administration, not by a login.
/// </summary>
public sealed class AuthCenterWeak : IAuthCenterScheme
{
    /// <inheritdoc />
    public string ProviderName => ActorInfo.WeakScheme;

    /// <inheritdoc />
    public IEnumerable<string> Schemes => [ActorInfo.WeakScheme];

    /// <inheritdoc />
    public bool AllowsAccountCreation( string scheme ) => false;
}
