using CK.Core;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Immutable protocol map negotiated with the remote party.
    /// </summary>
    public readonly struct MessageProtocolMap
    {
        /// <summary>
        /// The maximal number of protocols that 2 parties can use after negotiation.
        /// This is also the greatest possible protocol number.
        /// </summary>
        public const int MaxCount = 7;

        readonly MessageProtocol[] _protocols;

        MessageProtocolMap( MessageProtocol[] protocols )
        {
            _protocols = protocols;
        }

        /// <summary>
        /// Gets a <see cref="MessageProtocolMap"/> for the provided set of protocols.
        /// </summary>
        /// <param name="protocols">
        /// The list of supported protocols that has been negotiated with the other party.
        /// Must not be empty, contain more than <see cref="MaxCount"/> protocols, contain duplicates <see cref="MessageProtocol.Name"/>
        /// or any invalid or "0 Protocol".
        /// </param>
        /// <returns>The map to use.</returns>
        public static MessageProtocolMap Get( IEnumerable<MessageProtocol> protocols )
        {
            Throw.CheckNotNullArgument( protocols );
            return InternalGet( protocols.OrderBy( p => p.Name ).ToArray() );
        }

        internal static MessageProtocolMap InternalGet( MessageProtocol[] protocols )
        {
            CheckProtocolArrayArgument( protocols );
            return new MessageProtocolMap( protocols );

            static void CheckProtocolArrayArgument( MessageProtocol[] protocols )
            {
                Throw.CheckNotNullArgument( protocols );
                Throw.CheckArgument( protocols.Length > 0 && protocols.Length <= MaxCount );
                Throw.CheckArgument( protocols.All( p => p != null && p != MessageProtocol.ZeroProtocol ) );
                Throw.CheckArgument( protocols.Select( p => p.Name ).IsSortedStrict() );
            }
        }

        /// <summary>
        /// See <see cref="Get(IEnumerable{MessageProtocol})"/>.
        /// Mainly for tests (the array is cloned anyway for safety).
        /// </summary>
        /// <param name="protocols">The protocols.</param>
        /// <returns>The map to use.</returns>
        public static MessageProtocolMap Get( params MessageProtocol[] protocols ) => Get( (IEnumerable<MessageProtocol>)protocols );

        /// <summary>
        /// Gets whether this map is valid.
        /// </summary>
        public bool IsValid => _protocols != null;

        /// <summary>
        /// Gets the ordered list of protocols.
        /// </summary>
        public IReadOnlyList<MessageProtocol> Protocols => _protocols ?? Array.Empty<MessageProtocol>();

        /// <summary>
        /// Tries to find a <see cref="MessageProtocol"/> by its number in this map.
        /// </summary>
        /// <param name="number">The protocol number to find.</param>
        /// <param name="p">The resulting protocol.</param>
        /// <returns>True on success, false if the number is incorrect.</returns>
        public bool TryFind( byte number, [NotNullWhen(true)]out MessageProtocol? p )
        {
            if( number == 0 )
            {
                p = MessageProtocol.ZeroProtocol;
                return true;
            }
            if( _protocols == null || number > _protocols.Length )
            {
                p = null;
                return false;
            }
            p = _protocols[number - 1];
            return true;
        }

        /// <summary>
        /// Gets the protocol number for a given message protocol.
        /// </summary>
        /// <param name="protocol">The protocol.</param>
        /// <returns>The protocol number or -1 if not found.</returns>
        public int GetProtocolNumber( MessageProtocol protocol )
        {
            return protocol == MessageProtocol.ZeroProtocol
                    ? 0
                    : Array.IndexOf( _protocols, protocol ) + 1;
        }

    }

}
