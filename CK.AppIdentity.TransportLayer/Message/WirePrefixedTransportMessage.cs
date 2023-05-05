using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Message
{
    internal readonly struct WirePrefixedTransportMessage : IDisposable
    {
        internal const int IsControlFlag = 0b00100000;
        readonly IMemoryOwner<byte> _prefixBuffer;
        public ReadOnlyMemory<byte> Prefix { get; }
        public IMessage Message { get; }

        internal WirePrefixedTransportMessage( IMessage message, IMemoryOwner<byte> prefixBuffer, int bufferLength )
        {
            Debug.Assert( message != null );
            Message = message;
            _prefixBuffer = prefixBuffer;
            Prefix = prefixBuffer.Memory.Slice( 0, bufferLength );
        }

        public void Dispose()
        {
            Message.Dispose();
            _prefixBuffer.Dispose();
        }

        internal void SetProtocolNumber( int protocolNumber )
        {
            Debug.Assert( protocolNumber < 8 );
            var m = _prefixBuffer.Memory.Span;
            m[0] = (byte)((m[0] & 7) | protocolNumber);
        }

        internal int GetProtocolNumber() => Prefix.Span[0] & 7;
    }
}
