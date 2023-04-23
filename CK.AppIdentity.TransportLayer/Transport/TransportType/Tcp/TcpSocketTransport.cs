using CK.Core;
using System.Net.Sockets;

namespace CK.AppIdentity.TransportLayer
{
    sealed class TcpSocketTransport : Transport
    {
        readonly Socket _socket;

        public TcpSocketTransport( TcpSocketListener listener, Socket socket )
            : base( listener, socket.RemoteEndPoint?.ToString() )
        {
            _socket = socket;
        }

        public TcpSocketTransport( TransportTypeAddress targetAddress, Socket socket )
            : base( targetAddress, socket.RemoteEndPoint?.ToString() ?? targetAddress.TypedAddress.ToString() )
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

        protected override async ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default )
        {
            int len;
            while( (len = await _socket.SendAsync( buffer, SocketFlags.None, cancellationToken )) < buffer.Length )
            {
                buffer = buffer.Slice( len );
            }
        }
    }
}
