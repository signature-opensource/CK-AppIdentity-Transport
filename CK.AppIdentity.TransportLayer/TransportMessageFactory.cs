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
    /// Factory for <see cref="TransportMessage"/>. There is only 3 ways to create a transport message:
    /// <list type="number">
    /// <item><see cref="Create(Action{IBufferWriter{byte}}, int)"/> for outgoing messages that must be disposed</item>
    /// <item><see cref="ReadAsync(Func{Memory{byte}, CancellationToken, ValueTask}, long, CancellationToken)"/> for incoming messages that must be disposed.</item>
    /// <item><see cref="CreateStatic(Action{IBufferWriter{byte}}, int)"/> for messages that can be kept without the need to be disposed.</item>
    /// </list>
    /// <para>
    /// This class is thread safe.
    /// </para>
    /// </summary>
    public sealed class TransportMessageFactory : IDisposable
    {
        internal const int _maxPrefixLength = 5;

        MutableSequence<byte>? _oneBuffer;

        /// <summary>
        /// Creates a <see cref="TransportMessage"/> from an asynchronous buffer provider.
        /// This raises any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
        /// <paramref name="cancellation"/> token has been signaled, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// When <see cref="TransportMessage.Invalid"/> is returned it means that an invalid length prefix has been read or it exceeds
        /// the <paramref name="maxMessageLength"/> parameter. 
        /// </summary>
        /// <param name="exactReader">The reader to use.</param>
        /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>A message that may be the <see cref="TransportMessage.Invalid"/> or <see cref="TransportMessage.Empty"/>.</returns>
        public async Task<TransportMessage> ReadAsync( Func<Memory<byte>,CancellationToken,ValueTask> exactReader,
                                                       int maxMessageLength = -1,
                                                       CancellationToken cancellation = default )
        {
            Throw.CheckNotNullArgument( exactReader );
            if( maxMessageLength == -1 ) maxMessageLength = int.MaxValue;
            else Throw.CheckOutOfRangeArgument( maxMessageLength > 0 );

            var buffer = GetBuffer();
            try
            {
                // We work with an initial buffer of 4K. This is enough for small messages and
                // since we control the slicing, we ensure that we fill it.
                const int headLength = 4096;
                var header = buffer.GetMemory( headLength );
                Debug.Assert( buffer.Length == 0 );
                await exactReader( header.Slice( 0, 1 ), cancellation ).ConfigureAwait( false );
                int byteMessageLen = header.Span[0];
                if( byteMessageLen == 0 )
                {
                    return TransportMessage.Empty;
                }
                buffer.Advance( 1 );
                if( byteMessageLen < 128 )
                {
                    if( byteMessageLen > maxMessageLength ) return TransportMessage.Invalid;
                    // Everything fits in the header.
                    await exactReader( header.Slice( 1, byteMessageLen ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( byteMessageLen );
                    return new TransportMessage( this, buffer, 0, 1 );
                }
                // The length is on more than one byte. There must be at least 128 bytes
                // and we can fully handle the maximal 5 bytes prefix length.
                await exactReader( header.Slice( 1, 128 ), cancellation ).ConfigureAwait( false );
                // We don't use and don't expose the 4 bits high state yet.
                int lefToRead = ReadLength( header.Span, out int prefixLength, out byte _ );
                if( lefToRead == 0 || lefToRead > maxMessageLength ) return TransportMessage.Invalid;
                // We already read 129 bytes.
                buffer.Advance( 128 );
                header = header.Slice( 129 );
                lefToRead -= prefixLength;
                // Is the header buffer enough?
                if( lefToRead <= header.Length )
                {
                    header = header.Slice( 0, lefToRead );
                    await exactReader( header, cancellation ).ConfigureAwait( false );
                    buffer.Advance( header.Length );
                    return new TransportMessage( this, buffer, 0, prefixLength );
                }
                // There is more than the initial buffer. Fills it.
                await exactReader( header, cancellation ).ConfigureAwait( false );
                lefToRead -= header.Length;
                buffer.Advance( header.Length );
                Debug.Assert( buffer.CurrentlyAvailableLength == 0 && lefToRead > 0, "We totally filled the header but there's more to read." );
                // Huge messages are uncommon. We choose to process buffers limited to 64K to avoid the LOH.
                while( lefToRead >= 64 * 1024 )
                {
                    await exactReader( buffer.GetMemory( 64 * 1024 ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( 64 * 1024 );
                    lefToRead -= 64 * 1024;
                }
                if( lefToRead > 0 )
                {
                    await exactReader( buffer.GetMemory( lefToRead ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( lefToRead );
                }
                return new TransportMessage( this, buffer, 0, prefixLength );
            }
            catch( OperationCanceledException ) when (cancellation.IsCancellationRequested)
            {
                return TransportMessage.Canceled;
            }
            finally
            {
                Release( buffer );
            }

            static int ReadLength( Span<byte> header, out int prefixLength, out byte highState )
            {
                ref byte readHead = ref MemoryMarshal.GetReference( header );
                ulong result = Unsafe.ReadUnaligned<ulong>( ref readHead );
                var bytesNeeded = BitOperations.TrailingZeroCount( (uint)result ) + 1;
                prefixLength = bytesNeeded;
                if( bytesNeeded > 5 )
                {
                    highState = 0;
                    return 0;
                }
                result &= (1UL << (bytesNeeded * 8)) - 1;
                result >>= bytesNeeded;
                highState = (byte)(result >> 31);
                return (int)(result & int.MaxValue);
            }
        }

        /// <summary>
        /// Creates a <see cref="TransportMessage"/> by writing its content.
        /// </summary>
        /// <param name="writer">The writer function.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A transport message (can be the <see cref="TransportMessage.Empty"/> if the <paramref name="writer"/> did nothing).</returns>
        public TransportMessage Create( Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var buffer = GetBuffer();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                return DoCreate( this, writer, buffer );
            }
            finally
            {
                Release( buffer );
            }
        }

        /// <summary>
        /// Creates a static snapshot <see cref="TransportMessage"/>, its content is a single independent segment (not pooled).
        /// <see cref="TransportMessage.Dispose()"/> on a static message does nothing.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static transport message.</returns>
        public static TransportMessage CreateStatic( Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var buffer = new MutableSequence<byte>();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                return DoCreate( null, writer, buffer );
            }
            finally
            {
                buffer.Dispose();
            }
        }

        static TransportMessage DoCreate( TransportMessageFactory? factory, Action<IBufferWriter<byte>> writer, MutableSequence<byte> buffer )
        {
            int prefixLength;
            // Reserves 5 bytes: this is the maximal prefix length.
            // We do not preallocate a 4K buffer here like we do while receiving:
            // It is up to the caller to specify this thanks to minSequenceBufferSize if she wants.
            var header = buffer.GetMemory( _maxPrefixLength );
            buffer.Advance( _maxPrefixLength );
            writer( buffer );
            if( buffer.Length > int.MaxValue ) Throw.InvalidOperationException( $"Buffered {buffer.Length} bytes exceeds {int.MaxValue} maximum TransportMessage size." );
            var messageLength = (int)buffer.Length - _maxPrefixLength;
            if( messageLength == 0 )
            {
                if( factory == null ) Throw.InvalidOperationException( "A static TransportMessage cannot be empty." );
                return TransportMessage.Empty;
            }
            Span<byte> prefix = stackalloc byte[_maxPrefixLength];
            prefixLength = WriteLength( messageLength, prefix, 0 );
            Debug.Assert( prefixLength <= _maxPrefixLength );
            int offset = _maxPrefixLength - prefixLength;
            prefix.CopyTo( header.Span.Slice( offset ) );
            if( factory == null )
            {
                var content = new ReadOnlySequence<byte>( buffer.GetReadOnlySequence(offset).ToArray() );
                return new TransportMessage( content, prefixLength );
            }
            return new TransportMessage( factory, buffer, offset, prefixLength );

            // When highState is non 0, we aways need 5 bytes prefix length.
            // Maximal highState is 15: 4 bits are available for flags (sticking with 5 bytes prefix).
            static int WriteLength( int value, Span<byte> memory, byte highState )
            {
                ulong uValue = (ulong)(uint)value | ((ulong)highState << 31);
                var neededBytes = (int)((uint)BitOperations.Log2( uValue ) / 7);
                ulong lower = ((uValue << 1) + 1) << neededBytes;
                if( !BitConverter.IsLittleEndian ) lower = BinaryPrimitives.ReverseEndianness( lower );
                Unsafe.WriteUnaligned( ref MemoryMarshal.GetReference( memory ), lower );
                return neededBytes + 1;
            }
        }

        MutableSequence<byte> GetBuffer()
        {
            return Interlocked.Exchange( ref _oneBuffer, null ) ?? new MutableSequence<byte>();
        }


        internal void Release( MutableSequence<byte> buffer )
        {
            buffer.Clear();
            Interlocked.CompareExchange( ref _oneBuffer, buffer, null );
        }

        /// <summary>
        /// Disposes any internal resource.
        /// </summary>
        public void Dispose()
        {
            Interlocked.Exchange( ref _oneBuffer, null )?.Dispose();
        }
    }
}
