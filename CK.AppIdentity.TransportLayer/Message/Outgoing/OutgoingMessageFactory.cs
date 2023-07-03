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
    /// Factory for <see cref="OutgoingMessageBuilder"/>.
    /// There is only 2 ways to create an outgoing transport message:
    /// <list type="number">
    /// <item><see cref="CreateBuilder()"/> (and then <see cref="OutgoingMessageBuilder.CreateMessage"/>) for regular messages (that must be disposed).</item>
    /// <item><see cref="CreateStatic(Action{IBufferWriter{byte}}, int)"/> for messages that can be kept without the need to be disposed.</item>
    /// </list>
    /// <para>
    /// This class is thread safe.
    /// </para>
    /// </summary>
    public sealed class OutgoingMessageFactory : IDisposable
    {
        readonly MessageProtocol _protocol;
        MutableSequence<byte>? _cachedOneBuffer;

        /// <summary>
        /// Initializes a new message factory for a protocol and its protocol number.
        /// </summary>
        /// <param name="protocol">The protocol. Must not be the "0 Protocol".</param>
        public OutgoingMessageFactory( MessageProtocol protocol )
        {
            Throw.CheckArgument( protocol != null && protocol != MessageProtocol.ZeroProtocol );
            _protocol = protocol;
        }

        /// <summary>
        /// Gets the protocol that this factory uses.
        /// </summary>
        public MessageProtocol Protocol => _protocol;

        /// <summary>
        /// Creates a new <see cref="OutgoingMessageBuilder"/>.
        /// Either <see cref="OutgoingMessageBuilder.Dispose"/> or <see cref="OutgoingMessageBuilder.CreateMessage"/> must be called on the builder.
        /// </summary>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A message builder.</returns>
        public OutgoingMessageBuilder Create( int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var buffer = GetBuffer();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            return new OutgoingMessageBuilder( this, buffer );
        }

        /// <summary>
        /// Creates a static snapshot <see cref="TransportMessage"/>, its content is a single independent segment (not pooled).
        /// <see cref="TransportMessage.Dispose()"/> on a static message does nothing.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="isControl">True to set the <see cref="TransportMessage.IsControl"/> bit.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static transport message.</returns>
        public TransportMessage CreateStatic( Action<IBufferWriter<byte>> writer,
                                              bool isControl = false,
                                              int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, writer, null, isControl, minSequenceBufferSize );
        }

        /// <inheritdoc cref="CreateStatic(Action{IBufferWriter{byte}}, bool, int)"/>
        public TransportMessage CreateStatic( Action<MutableSequence<byte>> writer,
                                              bool isControl = false,
                                              int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, null, writer, isControl, minSequenceBufferSize );
        }

        TransportMessage DoCreate( MessageFactory? factory,
                                   Action<IBufferWriter<byte>>? bufferwriter,
                                   Action<MutableSequence<byte>>? sequenceWriter,
                                   bool isControl,
                                   int minSequenceBufferSize )
        {
            Debug.Assert( (bufferwriter == null) != (sequenceWriter == null) );
            bool releaseBuffer = true;
            var buffer = GetBuffer();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                int prefixLength;
                // Reserves 5 bytes: this is the maximal prefix length.
                // We do not preallocate a 4K buffer here like we do while receiving:
                // It is up to the caller to specify this thanks to minSequenceBufferSize if she wants.
                var header = buffer.GetMemory( _maxPrefixLength );
                buffer.Advance( _maxPrefixLength );

                if( bufferwriter != null ) bufferwriter( buffer );
                else sequenceWriter!( buffer );

                if( buffer.Length > int.MaxValue ) Throw.InvalidOperationException( $"Buffered {buffer.Length} bytes exceeds {int.MaxValue} maximum TransportMessage size." );
                var messageLength = (uint)buffer.Length - _maxPrefixLength;
                if( messageLength == 0 )
                {
                    Throw.InvalidOperationException( $"A TransportMessage cannot be empty (protocol '{_protocol.FullName}')." );
                }
                Span<byte> prefix = stackalloc byte[_maxPrefixLength];
                prefixLength = WritePrefix( isControl, messageLength, prefix );
                Debug.Assert( prefixLength <= _maxPrefixLength );
                int offset = _maxPrefixLength - prefixLength;
                prefix.Slice( 0, prefixLength ).CopyTo( header.Span.Slice( offset, prefixLength ) );
                if( factory == null )
                {
                    var content = new ReadOnlySequence<byte>( buffer.GetReadOnlySequence( offset ).ToArray() );
                    return new TransportMessage( _protocol, content, prefixLength );
                }
                releaseBuffer = false;
                return new TransportMessage( factory, _protocol, buffer, offset, prefixLength );
            }
            finally
            {
                if( releaseBuffer ) Release( buffer );
            }


            static int WritePrefix( bool isControl, uint messageLength, Span<byte> memory )
            {
                Debug.Assert( memory.Length >= _maxPrefixLength );
                Debug.Assert( messageLength >= 0 );
                uint len = (uint)BitOperations.Log2( messageLength ) / 8;
                Debug.Assert( len >= 0 && len <= 3 );
                var b = (len << 6);
                if( isControl ) b |= TransportMessage.IsControlFlag;
                Debug.Assert( b >= 0 && b <= 255 );
                memory[0] = (byte)b;
                if( !BitConverter.IsLittleEndian ) messageLength = BinaryPrimitives.ReverseEndianness( messageLength );
                Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( memory ), 1 ), messageLength );
                return (int)len + 2;
            }
        }

        internal MutableSequence<byte> GetBuffer()
        {
            return Interlocked.Exchange( ref _cachedOneBuffer, null ) ?? new MutableSequence<byte>();
        }

        internal void Release( MutableSequence<byte> buffer )
        {
            buffer.Clear();
            Interlocked.CompareExchange( ref _cachedOneBuffer, buffer, null );
        }

        /// <summary>
        /// Disposes any internal resource.
        /// </summary>
        public void Dispose()
        {
            Interlocked.Exchange( ref _cachedOneBuffer, null )?.Dispose();
        }

    }

}
