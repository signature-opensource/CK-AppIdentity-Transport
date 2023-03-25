using CK.Core;
using System.Collections.Concurrent;

namespace CK.AppIdentity.TransportLayer
{

    /// <summary>
    /// Central registration for <see cref="MessageEncoding"/>.
    /// </summary>
    public sealed class MessageEncodingDirectoryService : ISingletonAutoService
    {
        readonly ConcurrentDictionary<string, MessageEncoding> _encodings;

        /// <summary>
        /// Initializes a new empty directory.
        /// </summary>
        public MessageEncodingDirectoryService()
        {
            _encodings = new ConcurrentDictionary<string, MessageEncoding>();
        }

        /// <summary>
        /// Registers an encoding. 
        /// </summary>
        /// <param name="name">Encoding name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this encoding is specific to the parties.</param>
        /// <returns>The unique registration.</returns>
        public MessageEncoding Register( string name, bool isPartySpecific = false )
        {
            Throw.CheckNotNullOrWhiteSpaceArgument( name );
            if( name == MessageEncoding.ZeroProtocol.Name )
            {
                return MessageEncoding.ZeroProtocol;
            }
            var registered = _encodings.AddOrUpdate( name, new MessageEncoding( name, isPartySpecific ), ( n, exist ) => exist );
            if( registered.IsPartySpecific != isPartySpecific )
            {
                Throw.ArgumentException( $"Encoding '{name}' is already registered with IsPartySpecific = {registered.IsPartySpecific}." );
            }
            return registered;
        }

        /// <summary>
        /// Tries to register an encoding: the name must be valid, not "0 Protocol" and no already
        /// registered encoding with same name exist with a different <see cref="MessageEncoding.IsPartySpecific"/>.
        /// </summary>
        /// <param name="name">Encoding name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this encoding is specific to the parties.</param>
        /// <param name="registered">The registered message encoding on success.</param>
        /// <returns>True on success, false otherwise.</returns>
        public bool TryRegister( string name, bool isPartySpecific, out MessageEncoding registered )
        {
            if( !string.IsNullOrWhiteSpace( name ) && name != MessageEncoding.ZeroProtocol.Name )
            {
                var r = _encodings.AddOrUpdate( name, new MessageEncoding( name, isPartySpecific ), ( n, exist ) => exist );
                if( r.IsPartySpecific == isPartySpecific )
                {
                    registered = r;
                    return true;
                }
            }
            registered = MessageEncoding.ZeroProtocol;
            return false;
        }
    }
}
