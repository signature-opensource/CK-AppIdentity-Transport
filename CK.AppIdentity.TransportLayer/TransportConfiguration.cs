using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The configuration of the "Transport" feature of a party (<see cref="TransportFeatureDriver"/>): the "Transport" section of
/// a local party's "Local" or of a remote, read key by key along the levels (the party, then the "Defaults" above it).
/// <code>
/// "Transport": {
///   "ListeningAddress": { "tcp": "0.0.0.0:37120", "mtls": "0.0.0.0:37121" },
///   "ListeningTypes": [ "mtls" ],
///   "AlwaysListening": true,
///   "DisallowEviction": false,
///   "NegotiationTimeout": 30
/// }
/// </code>
/// </summary>
[ConfigurationModel]
public sealed class TransportConfiguration : IConfigurationModel
{
    /// <summary>
    /// Gets the listening addresses by transport type ("tcp", "mtls"...): the address is an IP address (the interface to
    /// bind: "0.0.0.0", "[::]") with an optional port. The entries are merged along the levels, the nearest winning for a
    /// type: a dedicated address can be defined for a tenant domain (in its "Defaults") or for a remote.
    /// </summary>
    public IReadOnlyDictionary<string, string>? ListeningAddress { get; init; }

    /// <summary>
    /// Gets the transport types that the party listens on, among its listening addresses ("all" for all of them, the default).
    /// </summary>
    public IReadOnlyList<string>? ListeningTypes { get; init; }

    /// <summary>
    /// Gets whether a local party listens from its start (by default, it listens when the first remote without
    /// address appears).
    /// </summary>
    public bool AlwaysListening { get; init; }

    /// <summary>
    /// Gets whether a listening remote can't be evicted by a new incoming connection.
    /// </summary>
    public bool DisallowEviction { get; init; }

    /// <summary>
    /// Gets the timeout of the negotiation of a connection initiated to a remote, in seconds (between 1 and 600).
    /// </summary>
    public int? NegotiationTimeout { get; init; }

    /// <inheritdoc />
    public void Validate( IConfigurationValidationContext context )
    {
        if( NegotiationTimeout is < 1 or > 600 ) context.Error( $"'{context.Path}:NegotiationTimeout' is {NegotiationTimeout}: a number of seconds between 1 and 600 is expected." );
        if( ListeningTypes is { Count: 0 } ) context.Error( $"'{context.Path}:ListeningTypes' is empty: at least one transport type (or \"all\") is expected." );
    }
}
