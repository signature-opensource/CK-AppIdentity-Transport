using CK.Auth;
using CK.Core;
using System;

namespace CK.AppIdentity.Cris
{
    public interface IAuthenticationInfoTokenService : ISingletonAutoService
    {
        string CreateAuthenticationToken( IAuthenticationInfo info );

        /// <summary>
        /// Tries to parse a previously created by <see cref="CreateAuthenticationToken(IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="token">The string to parse.</param>
        /// <returns>The authentication info or null if the token cannot be parsed.</returns>
        IAuthenticationInfo? TryParseAuthenticationToken( ReadOnlySpan<char> token );
    }
}
