using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace CK.AppIdentity.TransportLayer;

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
    /// It can be empty but must not contain more than <see cref="MaxCount"/> protocols, contain duplicates <see cref="MessageProtocol.Name"/>
    /// or any invalid or the "0 Protocol".
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
            Throw.CheckArgument( protocols.Length <= MaxCount );
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
    /// Gets the ordered list of protocols. The "0 Protocol" is not in this list. 
    /// </summary>
    public IReadOnlyList<MessageProtocol> Protocols => _protocols ?? Array.Empty<MessageProtocol>();

    /// <summary>
    /// Gets the index of the protocol in the <see cref="Protocols"/>.
    /// The "0 Protocol" is not in this list: when this returns the 0 index (the first protocol), the protocol
    /// number is 1.
    /// </summary>
    /// <param name="protocol">The protocol.</param>
    /// <returns>The protocol index or -1 if not found.</returns>
    public int GetProtocolIndex( MessageProtocol protocol ) => Array.IndexOf( _protocols, protocol );

    /// <summary>
    /// Tries to find a protocol and its number from its <see cref="MessageProtocol.Name"/>.
    /// </summary>
    /// <param name="name">The protocol name.</param>
    /// <param name="protocol">The protocol or null.</param>
    /// <param name="protocolNumber">The protocol number if found.</param>
    /// <returns>True on success, false otherwise.</returns>
    public bool TryFindVersionedProtocol( string name, [NotNullWhen(true)]out MessageProtocol? protocol, out int protocolNumber )
    {
        if( name == MessageProtocol.ZeroProtocolName )
        {
            protocol = MessageProtocol.ZeroProtocol;
            protocolNumber = 0;
            return true;
        }
        for( int i = 0; i < _protocols.Length; i++ )
        {
            var p = _protocols[i];
            if( p.Name == name )
            {
                protocol = p;
                protocolNumber = i + 1;
                return true;
            }
        }
        protocol = null;
        protocolNumber = -1;
        return false;
    }

    internal int GetProtocolIndexByName( string name )
    {
        Throw.DebugAssert( name != MessageProtocol.ZeroProtocolName );
        for( int i = 0; i < _protocols.Length; i++ )
        {
            var p = _protocols[i];
            if( p.Name == name ) return i;
        }
        return -1;
    }

    /// <summary>
    /// Overridden to return "Invalid", "No Protocol" or the protocols' full name.
    /// </summary>
    /// <returns>The protocols.</returns>
    public override string ToString() => _protocols == null
                                            ? "Invalid"
                                            : _protocols.Length > 0
                                                ? _protocols.Select( p => p.FullName ).Concatenate()
                                                : "No Protocol";
}
