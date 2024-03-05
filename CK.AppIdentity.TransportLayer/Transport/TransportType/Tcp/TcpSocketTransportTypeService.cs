using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// This is the default type of transport. When a <see cref="IRemoteParty.Address"/> has no prefix,
    /// it is assumed to be "tcp".
    /// </summary>
    public sealed class TcpSocketTransportTypeService : TransportTypeService
    {
        const int DefaultPort = 37120;
        readonly IPEndPoint _defaultEndPoint;

        public TcpSocketTransportTypeService()
            : base( "tcp" )
        {
            _defaultEndPoint = new IPEndPoint( IPAddress.Any, DefaultPort );
        }

        /// <summary>
        /// Gets the default listening address on any interface, port 37120.
        /// </summary>
        /// <returns>The default 'tcp' listening address.</returns>
        public override object? DefaultListeningAddress => _defaultEndPoint;

        /// <inheritdoc />
        public override TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, ImmutableConfigurationSection section )
        {
            if( IPEndPoint.TryParse( typed, out var endPoint ) )
            {
                if( endPoint.Port == 0 ) endPoint.Port = DefaultPort;
                return new TransportTypeAddress( this, section, endPoint );
            }
            monitor.Error( $"Invalid '{section.Path}' = '{typed}'. It must be an IPAddress with an optional port (defaults to {DefaultPort})." );
            return null;
        }

        /// <inheritdoc />
        internal protected override async Task<Transport?> TryConnectAsync( IParallelLogger logger,
                                                                            TransportTypeAddress typedAddress,
                                                                            IRemoteKeys remoteKeys,
                                                                            CancellationToken cancellation )
        {
            var ipEndPoint = (IPEndPoint)typedAddress.TypedAddress;
            var socket = new Socket( SocketType.Stream, ProtocolType.Tcp );
            try
            {
                await socket.ConnectAsync( ipEndPoint, cancellation ).ConfigureAwait( false );
                return new TcpSocketTransport( typedAddress, socket, remoteKeys );
            }
            catch( Exception ex )
            {
                logger.Error( $"Unable to connect a TCP socket to '{ipEndPoint}'.", ex );
                socket.Dispose();
                return null;
            }
        }

        /// <inheritdoc />
        internal protected override TransportListener? TryCreateListener( IActivityMonitor monitor, object opaqueHandle, object typedAddress )
        {
            var ipEndPoint = (IPEndPoint)typedAddress;
            try
            {
                // This constructor sets DualMode = true if Socket.OSSupportsIPv6 is true.
                Socket socket = new Socket( SocketType.Stream, ProtocolType.Tcp );
                socket.Bind( ipEndPoint );
                socket.Listen();
                Throw.DebugAssert( socket.LocalEndPoint is IPEndPoint );
                return new TcpSocketListener( this, opaqueHandle, ipEndPoint, socket );
            }
            catch( Exception ex )
            {
                monitor.Error( $"While creating TCP socket listener on '{ipEndPoint}'.", ex );
                return null;
            }
        }
    }
}
