using CK.Core;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Simple immutable encapsulation of a <see cref="TransportTypeService"/>, the configuration path of its
/// address and an address that it understands.
/// </summary>
/// <param name="Type">The transport type.</param>
/// <param name="Path">
/// The configuration path of the address: a "ListeningAddress" entry, an "Address", or the root of the configuration for a
/// default listening address.
/// </param>
/// <param name="TypedAddress">Specific address type.</param>
public sealed record class TransportTypeAddress( TransportTypeService Type,
                                                 string Path,
                                                 object TypedAddress )
{
    /// <summary>
    /// Describes this address: its transport type and its typed address ("host:port" for a host name).
    /// </summary>
    /// <returns>The description.</returns>
    public override string ToString() => $"{Type.GetType().Name} - {(TypedAddress is System.Net.DnsEndPoint d ? $"{d.Host}:{d.Port}" : TypedAddress)}";
}
