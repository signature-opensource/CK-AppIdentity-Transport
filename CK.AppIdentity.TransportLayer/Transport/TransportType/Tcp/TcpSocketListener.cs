using CK.Core;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    sealed class TcpSocketListener : TransportListener
    {
        readonly IPEndPoint _address;
        readonly Socket _listenSocket;
        readonly CancellationTokenSource _listenCTS;

        public TcpSocketListener( TcpSocketTransportTypeService tcpService, object opaqueHandle, IPEndPoint address, Socket listenSocket )
            : base( opaqueHandle, tcpService )
        {
            _address = address;
            _listenSocket = listenSocket;
            _listenCTS = new CancellationTokenSource();
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
            _listenCTS.Cancel();
            return default;
        }

        async Task RunAcceptAsync()
        {
            Logger.Info( $"Starting '{ToString()}'." );
            while( true )
            {
                try
                {
                    var acceptSocket = await _listenSocket.AcceptAsync( _listenCTS.Token );
                    // Disable Nagle algorithm: a message is fully buffered. We don't need it.
                    acceptSocket.NoDelay = true;
                    OnIncomingTransport( new TcpSocketTransport( this, acceptSocket ) );
                }
                catch( OperationCanceledException ) when( _listenCTS.IsCancellationRequested ) 
                {
                    // Token signaled. We're done.
                    break;
                }
                catch( SocketException e ) when( e.SocketErrorCode == SocketError.OperationAborted )
                {
                    // Dispose called: we're done
                    break;
                }
                catch( SocketException ex )
                {
                    Logger.Warn( $"An incoming TCP connection got reset while it was in the backlog on '{_address}'.", ex );
                }
                catch( Exception ex )
                {
                    Logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Unexpected error in TCP listener on '{_address}'.", ex );
                }
            }
            Logger.Info( $"Ending '{ToString()}' (disposing Listening socket)." );
            try
            {
                _listenSocket.Dispose();
            }
            catch( Exception ex )
            {
                Logger.Error( "While disposing TCP listener.", ex );
            }

        }
    }
}
