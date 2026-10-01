using CK.AppIdentity.TransportLayer;
using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace CK.Testing.AppIdentity.TransportLayer;

/// <summary>
/// Funny helper that transforms a <see cref="IOutgoingMessage"/> into a
/// piece of stream that can be used to read back a <see cref="IncomingMessage"/>.
/// <para>
/// There is no optimization here: the outgoing message payload is copied in a byte array
/// after its wire prefix.
/// </para>
/// </summary>
public class BasicAsyncReader
{
    byte[] _data;
    int _offset;

    public BasicAsyncReader( IOutgoingMessage m, MessageProtocolMap negotiatedProtocols )
    {
        var bytes = new byte[m.Message.Length + IOutgoingMessage.MaxWirePrefixLength];
        int lenHeader = IOutgoingMessage.WriteWireHeader( negotiatedProtocols, m, bytes );
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
