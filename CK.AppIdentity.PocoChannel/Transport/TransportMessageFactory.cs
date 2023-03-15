using System.Buffers;

namespace CK.AppIdentity.PocoChannel
{
    public class TransportMessageFactory
    {
        readonly BufferEditorFactory _bufferFactory;
        BufferEditorFactory.Buffer? _oneBuffer;

        public TransportMessageFactory()
        {
            _bufferFactory = new BufferEditorFactory();
        }

        public TransportMessage Create( Action<IBufferWriter<byte>> writer )
        {
            BufferEditorFactory.Buffer buffer;
            int prefixLength;
            lock( _bufferFactory )
            {
                buffer = _oneBuffer ?? _bufferFactory.CreateBuffer();
                // Reserve 9 bytes: this is the maximal prefix length.
                var header = buffer.GetMemory( 9 );
                buffer.Advance( 9 );
                writer( buffer );
                Span<byte> prefix = stackalloc byte[9];
                prefixLength = Write7BitEncodedInt64( buffer.Length, prefix );
                int offset = 9 - prefixLength;
                prefix.CopyTo( header.Span.Slice( offset ) );
            }
            return new TransportMessage( this, buffer, prefixLength );

            static int Write7BitEncodedInt64( long value, Span<byte> memory )
            {
                ulong uValue = (ulong)value;
                int i = 0;
                while( uValue > 0x7Fu )
                {
                    memory[i++] = (byte)((uint)uValue | ~0x7Fu);
                    uValue >>= 7;
                }
                memory[i++] = (byte)uValue;
                return i;
            }
        }


        internal void Release( BufferEditorFactory.Buffer buffer )
        {
            lock( _bufferFactory )
            {
                buffer.Clear();
                _oneBuffer ??= buffer;
            }
        }
    }
}
