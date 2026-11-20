using CK.Core;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Simple immutable encapsulation of a <see cref="TransportTypeService"/>, its originating
/// configuration section and an address that it understands.
/// </summary>
/// <param name="Type">The transport type.</param>
/// <param name="Section">
/// The configuration section: <see cref="ImmutableConfigurationSection.Key"/> is either "ListeningAddress" or "Address".
/// </param>
/// <param name="TypedAddress">Specific address type.</param>
public sealed record class TransportTypeAddress( TransportTypeService Type,
                                                 ImmutableConfigurationSection Section,
                                                 object TypedAddress )
{
    /// <summary>
    /// Describes this address: its transport type and its typed address ("host:port" for a host name).
    /// </summary>
    /// <returns>The description.</returns>
    public override string ToString() => $"{Type.GetType().Name} - {(TypedAddress is System.Net.DnsEndPoint d ? $"{d.Host}:{d.Port}" : TypedAddress)}";
}
