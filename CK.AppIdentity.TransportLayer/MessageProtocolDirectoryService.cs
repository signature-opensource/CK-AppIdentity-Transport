using CK.Core;
using System.Collections.Concurrent;

namespace CK.AppIdentity.TransportLayer
{

    /// <summary>
    /// Central registration for <see cref="MessageProtocol"/>.
    /// </summary>
    public sealed class MessageProtocolDirectoryService : ISingletonAutoService
    {
        readonly ConcurrentDictionary<string, MessageProtocol> _protocols;

        /// <summary>
        /// Initializes a new empty directory.
        /// </summary>
        public MessageProtocolDirectoryService()
        {
            _protocols = new ConcurrentDictionary<string, MessageProtocol>();
        }

        /// <summary>
        /// Registers a protocol. 
        /// </summary>
        /// <param name="name">Protocol name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this protocol is specific to the parties.</param>
        /// <returns>The unique registration.</returns>
        public MessageProtocol Register( string name, bool isPartySpecific = false )
        {
            Throw.CheckNotNullOrWhiteSpaceArgument( name );
            Throw.CheckArgument( name.Length <= MessageProtocol.NameMaxLength );
            if( name == MessageProtocol.ZeroProtocol.Name )
            {
                return MessageProtocol.ZeroProtocol;
            }
            var registered = _protocols.AddOrUpdate( name, new MessageProtocol( name, isPartySpecific ), ( n, exist ) => exist );
            if( registered.IsPartySpecific != isPartySpecific )
            {
                Throw.ArgumentException( $"Protocol '{name}' is already registered with IsPartySpecific = {registered.IsPartySpecific}." );
            }
            return registered;
        }

        /// <summary>
        /// Tries to register a protocol: the name must be valid, not "0 Protocol" and no already
        /// registered protocol with same name exist with a different <see cref="MessageProtocol.IsPartySpecific"/>.
        /// </summary>
        /// <param name="name">Protocol name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this protocol is specific to the parties.</param>
        /// <param name="registered">The registered message protocol on success.</param>
        /// <returns>True on success, false otherwise.</returns>
        public bool TryRegister( string name, bool isPartySpecific, out MessageProtocol registered )
        {
            if( !string.IsNullOrWhiteSpace( name ) && name != MessageProtocol.ZeroProtocol.Name )
            {
                var r = _protocols.AddOrUpdate( name, new MessageProtocol( name, isPartySpecific ), ( n, exist ) => exist );
                if( r.IsPartySpecific == isPartySpecific )
                {
                    registered = r;
                    return true;
                }
            }
            registered = MessageProtocol.ZeroProtocol;
            return false;
        }
    }
}
