using FluentAssertions;
using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests
{
    class BasicAsyncReader
    {
        byte[] _data;
        int _offset;

        public BasicAsyncReader( IOutgoingMessage m, MessageProtocolMap protocols )
        {
            var bytes = new byte[m.Message.Length + 5];
            var protocolNumber = protocols.GetProtocolIndex( m.Protocol );
            protocolNumber.Should().NotBe( -1 );
            int lenHeader = IOutgoingMessage.WriteWireHeader( protocolNumber + 1, m, bytes.AsSpan( 0, 5 ) );
            m.Message.CopyTo( bytes.AsSpan( lenHeader ) );
            _data = bytes;
        }

        public ValueTask ReadExactlyAsync( Memory<byte> memory, CancellationToken cancellation )
        {
            _data.AsSpan( _offset, memory.Length ).CopyTo( memory.Span );
            _offset += memory.Length;
            return ValueTask.CompletedTask;
        }
    }
}
