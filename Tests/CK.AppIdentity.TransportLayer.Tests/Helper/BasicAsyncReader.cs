using System.Buffers;

namespace CK.AppIdentity.TransportLayer.Tests
{
    class BasicAsyncReader
    {
        readonly ReadOnlySequence<byte> _seq;
        SequencePosition _position;

        public BasicAsyncReader( TransportMessage m )
        {
            _seq = m.WireMessage;
            _position = _seq.Start;
        }

        public ValueTask ReadExactlyAsync( Memory<byte> memory, CancellationToken cancellation )
        {
            _seq.Slice( _position, memory.Length ).CopyTo( memory.Span );
            _position = _seq.GetPosition( memory.Length, _position );
            return ValueTask.CompletedTask;
        }
    }
}
