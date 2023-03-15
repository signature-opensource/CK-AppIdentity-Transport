using CK.Core;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace CK.AppIdentity.PocoChannel
{

    sealed partial class ConnectionManager 
    {
        sealed class TcpSocketTransport : Transport
        {
            readonly Socket _socket;

            public TcpSocketTransport( ConnectionManager connectionManager, Socket socket, IListener? source )
                : base( connectionManager, source )
            {
                _socket = socket;
            }

            protected override ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellationToken = default )
            {
                return _socket.ReceiveAsync( buffer, SocketFlags.None, cancellationToken );
            }

            protected override async ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default )
            {
                int len;
                while( (len = await _socket.SendAsync( buffer, SocketFlags.None, cancellationToken )) < buffer.Length )
                {
                    buffer = buffer.Slice( len );
                }
            }
        }

        sealed class TcpSocketListener : IListener
        {
            readonly ConnectionManager _server;
            readonly IPEndPoint _address;
            readonly Socket _listenSocket;

            IRemoteParty[] _parties;

            public TcpSocketListener( ConnectionManager server, IPEndPoint address, Socket listenSocket, IRemoteParty first )
            {
                _parties = new IRemoteParty[] { first };
                _server = server;
                _address = address;
                _listenSocket = listenSocket;
                _ = Task.Run( RunAcceptAsync );
            }

            public IPEndPoint Address => _address;

            public IPEndPoint ActualListeningAddress => (IPEndPoint)_listenSocket.LocalEndPoint!;

            public IReadOnlyList<IRemoteParty> Parties => _parties;

            public void AddParty( IRemoteParty party )
            {
                Debug.Assert( !_parties.Contains( party ) );
                Util.InterlockedAdd( ref _parties, party );
            }

            public void RemoveParty( IRemoteParty party )
            {
                Debug.Assert( _parties.Contains( party ) );
                Util.InterlockedRemove( ref _parties, party );
            }

            public void Dispose()
            {
                _listenSocket.Dispose();
            }

            async Task RunAcceptAsync()
            {
                _server._agent.Logger.Info( $"Starting TCP listener on '{_address}'." );
                while( true )
                {
                    try
                    {
                        var acceptSocket = await _listenSocket.AcceptAsync();
                        // Disable Nagle algorithm: a message is fully buffered. We don't need
                        // one more buffering.
                        acceptSocket.NoDelay = true;
                        _server.OnIncomingConnection( new TcpSocketTransport( _server, acceptSocket, this ) );
                    }
                    catch( ObjectDisposedException )
                    {
                        // Dispose called: we're done
                        break;
                    }
                    catch( SocketException e ) when( e.SocketErrorCode == SocketError.OperationAborted )
                    {
                        // Dispose called: we're done
                        break;
                    }
                    catch( SocketException )
                    {
                        _server._agent.Logger.Warn( $"An incoming TCP connection got reset while it was in the backlog on '{_address}'." );
                    }
                }
                _server._agent.Logger.Info( $"Ending TCP listener on '{_address}'." );
            }
        }
    }
}
