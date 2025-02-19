using System;
using CK.Core;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Defines a type of transport (singleton auto service).
/// Implementations must specialize the abstract <see cref="TransportTypeService"/> (this
/// interface cannot be implemented by any other types).
/// </summary>
[IsMultiple]
public interface ITransportTypeService : ISingletonAutoService
{
    /// <summary>
    /// Defines this type of communication protocol that <see cref="IRemoteParty.Address"/> can use as a prefix.
    /// Must be in lower case, be short and not contain ':'.
    /// <para>
    /// This is "tcp" for the embedded <see cref="TcpSocketTransportTypeService"/>.
    /// </para>
    /// </summary>
    string TypeName { get; }

    /// <summary>
    /// Tries to parse a specific address string.
    /// Any error must be logged and null must be returned.
    /// </summary>
    /// <param name="monitor">The monitor to signal errors.</param>
    /// <param name="typed">The portion to parse.</param>
    /// <param name="section">Configuration section: <see cref="ImmutableConfigurationSection.Key"/> is either "ListeningAddress" or "Address".</param>
    /// <returns>A typed address on success, false otherwise.</returns>
    TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, ImmutableConfigurationSection section );

    /// <summary>
    /// Gets a default typed address if this type of transport supports it or null.
    /// </summary>
    object? DefaultListeningAddress { get; }
}
