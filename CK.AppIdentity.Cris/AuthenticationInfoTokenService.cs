using CK.Auth;
using CK.Core;
using Microsoft.IO;
using System;
using System.IO;
using System.Text;

namespace CK.AppIdentity.Cris
{
    /// <summary>
    /// Default implementation of <see cref="IAuthenticationInfoTokenService"/> singleton service
    /// that can be specialized.
    /// </summary>
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
            using( var m = (RecyclableMemoryStream)Util.RecyclableStreamManager.GetStream() )
            using( var r = new BinaryReader( m ) )
            {
                Encoding.UTF8.GetBytes( token, m );
                try
                {
                    return _typeSystem.AuthenticationInfo.Read( r );
                }
                catch( InvalidDataException )
                {
                    return null;
                }
            }
        }
    }
}
