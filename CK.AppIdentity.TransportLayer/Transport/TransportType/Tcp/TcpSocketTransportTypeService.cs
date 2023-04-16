using CK.Core;
using System.Net.Sockets;
using System.Net;
using System.Diagnostics;
using Microsoft.Extensions.Configuration;

namespace CK.AppIdentity.TransportLayer
{

    /// <summary>
    /// This is the default type of transport. When a <see cref="IRemoteParty.Address"/> has no prefix,
    /// it is assumed to be "tcp".
    /// </summary>
    public sealed class TcpSocketTransportTypeService : TransportTypeService
    {
        const int DefaultPort = 37120;

        readonly TransportTypeAddress _defaultListeningAddress;

        public TcpSocketTransportTypeService()
        {
            _defaultListeningAddress = new TransportTypeAddress( this, new IPEndPoint( IPAddress.Any, DefaultPort ) );
        }

        /// <summary>
        /// Gets "tcp".
        /// </summary>
        public override string AddressProtocolName => "tcp";

        /// <summary>
        /// Gets the default listening address.
        /// </summary>
        public TransportTypeAddress DefaultListeningAddress => _defaultListeningAddress;

        /// <inheritdoc />
        public override TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, string configurationPath, string? configurationKey )
        {
            if( IPEndPoint.TryParse( typed, out var endPoint ) )
            {
                if( endPoint.Port == 0 ) endPoint.Port = DefaultPort;
                return new TransportTypeAddress( this, endPoint );
            }
            monitor.Error( $"Invalid '{string.Join( ':', configurationPath, configurationKey )}' = '{typed}'. It must be an IPAddress with an optional port (defaults to {DefaultPort})." );
            return null;
        }

        /// <inheritdoc />
        internal protected override async Task<Transport?> TryConnectAsync( IActivityLogger logger, TransportTypeAddress typedAddress, CancellationToken cancellation )
        {
            var ipEndPoint = (IPEndPoint)typedAddress.TypedAddress;
            var socket = new Socket( SocketType.Stream, ProtocolType.Tcp );
            try
            {
                await socket.ConnectAsync( ipEndPoint ).ConfigureAwait( false );
                return new TcpSocketTransport( typedAddress, socket );
            }
            catch( Exception ex )
            {
                socket.Dispose();
                logger.Error( $"Unable to connect a TCP socket to '{ipEndPoint}'.", ex );
                return null;
            }
        }

        /// <inheritdoc />
        protected override TransportListener? TryCreateListener( IActivityMonitor monitor, object typedAddress )
        {
            var ipEndPoint = (IPEndPoint)typedAddress;
            try
            {
                Socket socket;
                if( ipEndPoint.Address == IPAddress.Any && Socket.OSSupportsIPv6 )
                {
                    socket = new Socket( AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp );
                    socket.DualMode = true;
                    ipEndPoint.Address = IPAddress.IPv6Any;
                }
                else
                {
                    socket = new Socket( ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp );
                }
                socket.Bind( ipEndPoint );
                socket.Listen();
                Debug.Assert( socket.LocalEndPoint is IPEndPoint );
                return new TcpSocketListener( this, ipEndPoint, socket );
            }
            catch( Exception ex )
            {
                monitor.Error( $"While creating TCP socket listener on '{ipEndPoint}'.", ex );
                return null;
            }
        }
    }
}
