using CK.Auth;
using CK.Core;
using Microsoft.IO;
using System;
using System.IO;
using System.Text;

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

    public class AuthenticationInfoTokenService : IAuthenticationInfoTokenService
    {
        readonly IAuthenticationTypeSystem _typeSystem;

        public AuthenticationInfoTokenService( IAuthenticationTypeSystem typeSystem )
        {
            _typeSystem = typeSystem;
        }

        public virtual string CreateAuthenticationToken( IAuthenticationInfo info )
        {
            using( var m = (RecyclableMemoryStream)Util.RecyclableStreamManager.GetStream() )
            using( var w = new BinaryWriter( m ) )
            {
                _typeSystem.AuthenticationInfo.Write( w, info );
                w.Flush();
                return Encoding.UTF8.GetString( m.GetReadOnlySequence() );
            }
        }

        public virtual IAuthenticationInfo? TryParseAuthenticationToken( ReadOnlySpan<char> token )
        {
            _typeSystem.AuthenticationInfo.Read()
            throw new NotImplementedException();
        }
    }
}
