using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

sealed class TcpSocketTransport : Transport
{
    readonly Socket _socket;

    public TcpSocketTransport( TcpSocketListener listener, Socket socket )
        : base( listener, socket.RemoteEndPoint?.ToString() )
    {
        _socket = socket;
    }

    public TcpSocketTransport( TransportTypeAddress targetAddress, Socket socket, IRemoteKeys remoteKeys )
        : base( targetAddress, remoteKeys, socket.RemoteEndPoint?.ToString() ?? targetAddress.TypedAddress.ToString() )
    {
        _socket = socket;
    }

    protected override ValueTask DisposeAsync( IActivityMonitor monitor )
    {
        _socket.Dispose();
        return default;
    }

    protected override ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellationToken = default )
    {
        return _socket.ReceiveAsync( buffer, SocketFlags.None, cancellationToken );
    }

    internal protected override async ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default )
    {
        int len;
        while( (len = await _socket.SendAsync( buffer, SocketFlags.None, cancellationToken )) < buffer.Length )
        {
            buffer = buffer.Slice( len );
        }
    }
}
