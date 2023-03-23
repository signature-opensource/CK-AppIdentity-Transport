using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    sealed class TcpSocketTransport : Transport, IDisposable
    {
        readonly Socket _socket;

        public TcpSocketTransport( Socket socket, TcpSocketListener? source )
            : base( source, socket.RemoteEndPoint?.ToString() )
        {
            _socket = socket;
        }

        public void Dispose()
        {
            _socket.Dispose();
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
