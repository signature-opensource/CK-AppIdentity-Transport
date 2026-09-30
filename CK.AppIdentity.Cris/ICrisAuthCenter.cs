using CK.Auth;
using CK.Core;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Exposes the "AuthCenter" feature that can provide a <see cref="IAuthenticationInfo"/> for
/// this application in regard of the "AuthCenter" feature in locals' remotes.
/// </summary>
public interface ICrisAuthCenter : ISingletonAutoService
{
    /// <summary>
    /// Gets the authentication info that represents this application for the "AuthCenter" of the local <paramref name="party"/>'s remotes.
    /// </summary>
    /// <param name="party">This <see cref="IApplicationIdentityService"/> or a <see cref="ITenantDomainParty"/>.</param>
    /// <returns>The authentication info or null if there is no "AuthCenter" feature in the <see cref="ILocalParty.Remotes"/>.</returns>
    IAuthenticationInfo? GetAuthenticationInfo( ILocalParty party );
}
