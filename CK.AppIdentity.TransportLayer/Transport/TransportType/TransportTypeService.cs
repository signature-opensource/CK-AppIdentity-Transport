using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Base class for <see cref="ITransportTypeService"/> implementations.
/// </summary>
[CKTypeDefiner]
public abstract class TransportTypeService : ITransportTypeService
{
    readonly string _typeName;

    /// <summary>
    /// Initializes a new <see cref="TransportTypeService"/>.
    /// </summary>
    /// <param name="typeName">Must be short, contain only ASCII characters and full lowercase. Must not be "all".</param>
    protected TransportTypeService( string typeName )
    {
        Throw.CheckArgument( !String.IsNullOrWhiteSpace( typeName )
                             && typeName.All( c => char.IsAscii( c ) && char.IsLetterOrDigit( c ) && char.IsLower( c ) ) );
        Throw.CheckArgument( typeName != "all" );
        _typeName = typeName;
    }

    /// <inheritdoc/>
    public string TypeName => _typeName;

    /// <inheritdoc/>
    public abstract TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, string path );

    /// <summary>
    /// Parses a network end point: an IP address with an optional port (<c>127.0.0.1:3712</c>, <c>[::1]:3712</c>), that is
    /// an <see cref="IPEndPoint"/>, or a host name with an optional port (<c>auth3.example.com:3712</c>), that is a
    /// <see cref="DnsEndPoint"/>: the name is resolved when connecting, again at each connection, and every address it
    /// returns is tried. A missing port is the <paramref name="defaultPort"/>. A listening address must be an IP address
    /// (see <see cref="IsListeningEndPoint"/>).
    /// </summary>
    /// <param name="typed">The typed part of the address.</param>
    /// <param name="defaultPort">The port when there is none.</param>
    /// <param name="endPoint">The end point on success.</param>
    /// <returns>True on success, false when this is neither an IP address nor a host name.</returns>
    protected static bool TryParseEndPoint( ReadOnlySpan<char> typed, int defaultPort, [System.Diagnostics.CodeAnalysis.NotNullWhen( true )] out EndPoint? endPoint )
    {
        if( IPEndPoint.TryParse( typed, out var ip ) )
        {
            if( ip.Port == 0 ) ip.Port = defaultPort;
            endPoint = ip;
            return true;
        }
        endPoint = null;
        var host = typed;
        int port = defaultPort;
        int idx = typed.LastIndexOf( ':' );
        if( idx >= 0 )
        {
            if( !int.TryParse( typed.Slice( idx + 1 ), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out port )
                || port <= 0 || port > IPEndPoint.MaxPort )
            {
                return false;
            }
            host = typed.Slice( 0, idx );
        }
        if( host.Length == 0 || Uri.CheckHostName( host.ToString() ) != UriHostNameType.Dns ) return false;
        endPoint = new DnsEndPoint( host.ToString(), port );
        return true;
    }

    /// <summary>
    /// Gets whether an end point parsed by <see cref="TryParseEndPoint"/> can be a listening address: an IP address (the
    /// interface to bind: <c>0.0.0.0</c>, <c>[::]</c>), not a host name.
    /// </summary>
    /// <param name="typedAddress">The typed address.</param>
    /// <returns>True for an IP end point.</returns>
    public static bool IsListeningEndPoint( object typedAddress ) => typedAddress is not DnsEndPoint;

    /// <summary>
    /// Describes an end point for the logs: "host:port" for a host name (not the "Unspecified/host:port" of
    /// <see cref="DnsEndPoint.ToString()"/>).
    /// </summary>
    /// <param name="endPoint">The end point.</param>
    /// <returns>Its description.</returns>
    protected static string Describe( EndPoint endPoint ) => endPoint is DnsEndPoint d ? $"{d.Host}:{d.Port}" : endPoint.ToString() ?? "";

    /// <summary>
    /// Gets a default typed address if this type of transport supports it.
    /// Returns null by default.
    /// </summary>
    public virtual object? DefaultListeningAddress => null;

    /// <summary>
    /// Creates a new listener: the <paramref name="typedAddress"/> is not currently listening.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="opaqueHandle">Opaque handle that mus be provided as-is to the <see cref="TransportListener()"/></param>
    /// <param name="typedAddress">The listening end point (necessarily a compatible address that has been parsed by this service).</param>
    /// <returns>The transport listener or null if it cannot be created.</returns>
    internal protected abstract TransportListener? TryCreateListener( IActivityMonitor monitor, object opaqueHandle, object typedAddress );

    /// <summary>
    /// Attempts a connection to the provided <paramref name="typedAddress"/>.
    /// If connection is not possible, any exception may be thrown but preferably a null <see cref="Transport"/>
    /// should be returned and the <paramref name="logger"/> be used to log a detailed error.
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="typedAddress">The target end point (that has been successfully parsed by this service).</param>
    /// <param name="remoteKeys">Remote key manager of this calling party.</param>
    /// <param name="cancellation">Cancellation token that will be signaled if the connection attempt timeout is reached.</param>
    /// <returns>A Transport or null.</returns>
    internal protected abstract Task<Transport?> TryConnectAsync( IParallelLogger logger,
                                                                  TransportTypeAddress typedAddress,
                                                                  IRemoteKeys remoteKeys,
                                                                  CancellationToken cancellation );
}
