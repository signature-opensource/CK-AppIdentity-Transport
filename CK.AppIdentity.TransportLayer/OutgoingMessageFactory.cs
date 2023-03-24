using CK.Core;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Factory for outgoing <see cref="TransportMessage"/>.
    /// There is only 2 ways to create an outgoing transport message:
    /// <list type="number">
    /// <item><see cref="Create(Action{IBufferWriter{byte}}, int)"/> for messages that must be disposed</item>
    /// <item>The static <see cref="CreateStatic(byte,Action{IBufferWriter{byte}}, int)"/> for messages that can be kept without the need to be disposed.</item>
    /// </list>
    /// <para>
    /// This class is thread safe.
    /// </para>
    /// </summary>
    public sealed class OutgoingMessageFactory : MessageFactory
    {
        byte _protocolNumber;

        /// <summary>
        /// Constructor for the "0" protocol.
        /// </summary>
        internal OutgoingMessageFactory()
        {
        }

        /// <summary>
        /// Initializes a new message factory for a given <see cref="TransportMessage.ProtocolNumber"/>.
        /// </summary>
        /// <param name="defaultProtocolNumber">Must be between 1 and 63.</param>
        public OutgoingMessageFactory( byte defaultProtocolNumber )
        {
            Throw.CheckOutOfRangeArgument( defaultProtocolNumber > 0 && defaultProtocolNumber < 64 );
            _protocolNumber = defaultProtocolNumber;
        }

        /// <summary>
        /// Creates a <see cref="TransportMessage"/> by writing its content.
        /// </summary>
        /// <param name="writer">The writer function.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A transport message (can be the <see cref="TransportMessage.Empty"/> if the <paramref name="writer"/> did nothing).</returns>
        public TransportMessage Create( Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( this, writer, minSequenceBufferSize, _protocolNumber );
        }

        /// <summary>
        /// Creates a static snapshot <see cref="TransportMessage"/>, its content is a single independent segment (not pooled).
        /// <see cref="TransportMessage.Dispose()"/> on a static message does nothing.
        /// </summary>
        /// <param name="protocolNumber">The protocol number.</param>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static transport message.</returns>
        public static TransportMessage CreateStatic( byte protocolNumber, Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, writer, minSequenceBufferSize, protocolNumber );
        }

        static TransportMessage DoCreate( MessageFactory? factory, Action<IBufferWriter<byte>> writer, int minSequenceBufferSize, byte protocolNumber )
        {
            bool releaseBuffer = true;
            var buffer = new MutableSequence<byte>();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                int prefixLength;
                // Reserves 5 bytes: this is the maximal prefix length.
                // We do not preallocate a 4K buffer here like we do while receiving:
                // It is up to the caller to specify this thanks to minSequenceBufferSize if she wants.
                var header = buffer.GetMemory( _maxPrefixLength );
                buffer.Advance( _maxPrefixLength );
                writer( buffer );
                if( buffer.Length > int.MaxValue ) Throw.InvalidOperationException( $"Buffered {buffer.Length} bytes exceeds {int.MaxValue} maximum TransportMessage size." );
                var messageLength = (uint)buffer.Length - _maxPrefixLength;
                if( messageLength == 0 )
                {
                    if( factory == null ) Throw.InvalidOperationException( "A static TransportMessage cannot be empty." );
                    return TransportMessage.Empty;
                }
                Span<byte> prefix = stackalloc byte[_maxPrefixLength];
                prefixLength = WritePrefix( protocolNumber, messageLength, prefix );
                Debug.Assert( prefixLength <= _maxPrefixLength );
                int offset = _maxPrefixLength - prefixLength;
                prefix.Slice( 0, prefixLength ).CopyTo( header.Span.Slice( offset, prefixLength ) );
                releaseBuffer = false;
                if( factory == null )
                {
                    var content = new ReadOnlySequence<byte>( buffer.GetReadOnlySequence( offset ).ToArray() );
                    return new TransportMessage( protocolNumber, content, prefixLength );
                }
                return new TransportMessage( factory, protocolNumber, buffer, offset, prefixLength );
            }
            finally
            {
                if( releaseBuffer ) buffer.Dispose();
            }


            static int WritePrefix( byte protocol, uint messageLength, Span<byte> memory )
            {
                Debug.Assert( memory.Length >= _maxPrefixLength );
                Debug.Assert( messageLength >= 0 && protocol < 64 );
                uint len = (uint)BitOperations.Log2( messageLength ) / 8;
                Debug.Assert( len >= 0 && len <= 3 );
                memory[0] = (byte)((len << 6) | protocol);
                if( !BitConverter.IsLittleEndian ) messageLength = BinaryPrimitives.ReverseEndianness( messageLength );
                Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( memory ), 1 ), messageLength );
                return (int)len + 2;
            }
        }
    }

}
