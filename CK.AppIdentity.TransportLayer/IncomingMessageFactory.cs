using CK.Core;
using System.Buffers.Binary;
using System;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Factory for ingoing <see cref="TransportMessage"/>.
    /// There is only 1 way to create an incoming transport message: reading it from an asynchronous buffer provider.
    /// <para>
    /// This class is thread safe.
    /// </para>
    /// </summary>
    public sealed class IncomingMessageFactory : MessageFactory
    {
        /// <summary>
        /// Initializes a new 
        /// </summary>
        /// <param name="allowed"></param>
        public IncomingMessageFactory( IEnumerable<MessageProtocol> allowed )
        {
            
        }

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
        public async Task<TransportMessage> ReadAsync( Func<Memory<byte>, CancellationToken, ValueTask> exactReader,
                                                       int maxMessageLength = -1,
                                                       CancellationToken cancellation = default )
        {
            Throw.CheckNotNullArgument( exactReader );
            if( maxMessageLength == -1 ) maxMessageLength = int.MaxValue;
            else Throw.CheckOutOfRangeArgument( maxMessageLength > 0 );

            bool releaseBuffer = true;
            var buffer = GetBuffer();
            try
            {
                // We work with an initial buffer of 4K. This is enough for small messages and
                // since we control the slicing, we ensure that we fill it.
                const int headLength = 4096;
                var header = buffer.GetMemory( headLength );
                Debug.Assert( buffer.Length == 0 );
                // We first read exactly 2 bytes. 
                await exactReader( header.Slice( 0, 2 ), cancellation ).ConfigureAwait( false );
                byte firstByte = header.Span[0];
                byte protocol = (byte)(firstByte & 0b00111111);
                int messageLength;
                int lenSize = firstByte >> 6;
                if( lenSize == 0 )
                {
                    // 1 byte length message. 
                    messageLength = header.Span[1];
                    if( messageLength > maxMessageLength ) return TransportMessage.Invalid;
                    if( messageLength == 0 )
                    {
                        return protocol == 0
                                ? TransportMessage.Empty
                                : Throw.InvalidDataException<TransportMessage>( $"Forbidden 0 length message received for protocol '{protocol}'." );
                    }
                    // The whole message (255 bytes max.) necessarily fits in the header.
                    await exactReader( header.Slice( 2, messageLength ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( 2 + messageLength );
                    releaseBuffer = false;
                    return new TransportMessage( this, protocol, buffer, offset: 0, prefixLength: 2 );
                }
                // The length is on more than one byte. There must be at least 256 bytes
                // and we can fully handle the maximal 5 bytes prefix: we must now use the lenSize
                // following bytes (1 to 3) to know the message length.
                await exactReader( header.Slice( 2, 256 ), cancellation ).ConfigureAwait( false );
                // Now we can compute the message length: the 1 to 3 bytes are here.
                messageLength = (int)(BinaryPrimitives.ReadUInt32LittleEndian( header.Slice( 1 ).Span ) & (uint)((1ul << (lenSize + 1 << 3)) - 1));
                // If the resulting length is less than 256, it means that the data is simply invalid.
                if( messageLength < 256 || messageLength > maxMessageLength )
                {
                    return TransportMessage.Invalid;
                }
                // We already read 2 + 256 = 258 bytes.
                buffer.Advance( 258 );
                // But we read 256 - lenSize bytes for the payload.
                messageLength -= 256 - lenSize;
                // What's left in our preallocated buffer?
                header = header.Slice( 258 );
                if( messageLength <= header.Length )
                {
                    header = header.Slice( 0, messageLength );
                    await exactReader( header, cancellation ).ConfigureAwait( false );
                    buffer.Advance( header.Length );
                    releaseBuffer = false;
                    return new TransportMessage( this, protocol, buffer, offset: 0, prefixLength: lenSize + 2 );
                }
                // There is more than the initial buffer. Fills it.
                await exactReader( header, cancellation ).ConfigureAwait( false );
                messageLength -= header.Length;
                buffer.Advance( header.Length );
                Debug.Assert( buffer.CurrentlyAvailableLength == 0 && messageLength > 0, "We totally filled the header but there's more to read." );
                // Huge messages are uncommon. We choose to process buffers limited to 64K to avoid the LOH.
                while( messageLength >= 64 * 1024 )
                {
                    await exactReader( buffer.GetMemory( 64 * 1024 ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( 64 * 1024 );
                    messageLength -= 64 * 1024;
                }
                if( messageLength > 0 )
                {
                    await exactReader( buffer.GetMemory( messageLength ).Slice( 0, messageLength ), cancellation ).ConfigureAwait( false );
                    buffer.Advance( messageLength );
                }
                releaseBuffer = false;
                return new TransportMessage( this, protocol, buffer, offset: 0, prefixLength: lenSize + 2 );
            }
            catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
            {
                return TransportMessage.Canceled;
            }
            finally
            {
                if( releaseBuffer ) Release( buffer );
            }
        }
    }

}
