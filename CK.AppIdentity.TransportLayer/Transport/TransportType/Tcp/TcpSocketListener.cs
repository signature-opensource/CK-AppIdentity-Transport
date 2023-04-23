using CK.Core;
using System.Net;
using System.Net.Sockets;

namespace CK.AppIdentity.TransportLayer
{
    sealed class TcpSocketListener : TransportListener
    {
        readonly IPEndPoint _address;
        readonly Socket _listenSocket;

        public TcpSocketListener( TcpSocketTransportTypeService tcpService, IPEndPoint address, Socket listenSocket )
            : base( tcpService )
        {
            _address = address;
            _listenSocket = listenSocket;
            _ = Task.Run( RunAcceptAsync );
        }

        public IPEndPoint Address => _address;

        public IPEndPoint ActualListeningAddress => (IPEndPoint)_listenSocket.LocalEndPoint!;

        public override string EndPointDescription
        {
            get
            {
                var a = _address;
                var r = ActualListeningAddress;
                if( !a.Equals( r ) )
                {
                    return $"TCP on {a} -> {r}";
                }
                return $"TCP on {a}";
            }
        }

        internal protected override bool IsListeningAddress( object address )
        {
            var ipEndPoint = (IPEndPoint)address;
            return ipEndPoint.Equals( Address ) || ipEndPoint.Equals( ActualListeningAddress );
        }

        internal protected override ValueTask DisposeAsync( IActivityMonitor monitor )
        {
            _listenSocket.Dispose();
            return default;
        }

        async Task RunAcceptAsync()
        {
            Logger.Info( $"Starting TCP listener on '{_address}'." );
            while( true )
            {
                try
                {
                    var acceptSocket = await _listenSocket.AcceptAsync();
                    // Disable Nagle algorithm: a message is fully buffered. We don't need it.
                    acceptSocket.NoDelay = true;
                    OnIncomingTransport( new TcpSocketTransport( this, acceptSocket ) );
                }
                catch( ObjectDisposedException )
                {
                    // Dispose called: we're done.
                    break;
                }
                catch( SocketException e ) when( e.SocketErrorCode == SocketError.OperationAborted )
                {
                    // Dispose called: we're done
                    break;
                }
                catch( SocketException )
                {
                    Logger.Warn( $"An incoming TCP connection got reset while it was in the backlog on '{_address}'." );
                }
            }
            Logger.Info( $"Ending TCP listener on '{_address}'." );
        }
    }
}
