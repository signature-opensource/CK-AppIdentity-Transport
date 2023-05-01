using CK.Auth;
using CK.Core;
using System;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// This service must be able to generate an opaque string token from a <see cref="IAuthenticationInfo"/>
    /// and parse it back.
    /// <para>
    /// Used on the executor/receiver/callee side. The caller obtains a string token by
    /// any means and transmits it as-is: it doesn't have to access the authentication information.
    /// </para>
    /// </summary>
    public interface IAuthenticationInfoTokenService : ISingletonAutoService
    {
        /// <summary>
        /// Creates an opaque token.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The token.</returns>
        string CreateAuthenticationToken( IAuthenticationInfo info );

        /// <summary>
        /// Tries to parse a previously created by <see cref="CreateAuthenticationToken(IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="token">The string to parse.</param>
        /// <returns>The authentication info or null if the token cannot be parsed.</returns>
        IAuthenticationInfo? TryParseAuthenticationToken( ReadOnlySpan<char> token );
    }
}
