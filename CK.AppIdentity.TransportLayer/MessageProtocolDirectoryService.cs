using CK.Core;
using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Central registration for <see cref="MessageProtocol"/>.
/// </summary>
public sealed class MessageProtocolDirectoryService : ISingletonAutoService, IDisposable
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
    /// Tries to register a protocol. Fails it the name is invalid, if it is the <see cref="MessageProtocol.ZeroProtocolName"/>
    /// or if the protocol is already registered with another <see cref="MessageProtocol.MaxIncomingMessageLength"/>.
    /// </summary>
    /// <param name="monitor">Required monitor.</param>
    /// <param name="name">Base protocol name.</param>
    /// <param name="version">Protocol version.</param>
    /// <param name="registered">The unique registration.</param>
    /// <returns>True on success, false otherwise.</returns>
    /// <param name="maxIncomingMessageLength">
    /// Cap on an incoming message of this protocol, 0 for <see cref="MessageProtocol.DefaultMaxIncomingMessageLength"/>.
    /// A channel that legitimately carries larger messages must raise it here: the declared length
    /// is attacker-chosen and is refused above this bound before anything is allocated for it.
    /// </param>
    public bool TryRegister( IActivityMonitor monitor,
                             string name,
                             ushort version,
                             [NotNullWhen( true )] out MessageProtocol? registered,
                             int maxIncomingMessageLength = 0 )
    {
        Throw.CheckNotNullArgument( name );
        name = name.Trim();
        if( name.Length == 0 || name.Contains( '.' ) || name.Equals( MessageProtocol.ZeroProtocol.Name, StringComparison.OrdinalIgnoreCase ) )
        {
            monitor.Error( $"Unable to register invalid protocol name '{name}'." );
        }
        else
        {
            var fullName = FormatFullName( name, version );
            var candidate = new MessageProtocol( fullName, name, version, false, maxIncomingMessageLength );
            registered = _protocols.GetOrAdd( fullName, candidate );
            if( registered.MaxIncomingMessageLength == candidate.MaxIncomingMessageLength )
            {
                return true;
            }
            monitor.Error( $"Protocol '{fullName}' is already registered with a maximum incoming message length of {registered.MaxIncomingMessageLength} bytes. It cannot be registered with {candidate.MaxIncomingMessageLength} bytes." );
        }
        registered = null;
        return false;
    }

    internal static string FormatFullName( string name, int version ) => $"{name}.{version}";

    void IDisposable.Dispose()
    {
        // Ensures that in tests contexts when disposing a root ServiceProvider, the
        // pooled messages (currently only one) is released.
        foreach( var protocol in _protocols.Values )
        {
            protocol.MessageFactory.Dispose();
        }
    }
}
