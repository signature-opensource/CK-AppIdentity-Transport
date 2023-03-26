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
        MessageProtocolMap _allowed;

        OutgoingMessageFactory()
        {
            // This map is not IsValid. 
            _allowed = new MessageProtocolMap();
        }

        /// <summary>
        /// Gets the factory for the TransportManager.
        /// </summary>
        internal static readonly OutgoingMessageFactory ZeroProtocol = new OutgoingMessageFactory();

        /// <summary>
        /// Initializes a new message factory for a protocol map. 
        /// </summary>
        /// <param name="protocols">
        /// A map that must be <see cref="MessageProtocolMap.IsValid"/> and negotiated
        /// with the other party.
        /// </param>
        public OutgoingMessageFactory( MessageProtocolMap protocols )
        {
            Throw.CheckArgument( protocols.IsValid );
            _allowed = protocols;
        }

        /// <summary>
        /// Gets the protocols map that this factory is allowed to handle.
        /// </summary>
        public MessageProtocolMap AllowedProtocols => _allowed;

        /// <summary>
        /// Creates a <see cref="TransportMessage"/> by writing its content.
        /// The <paramref name="writer"/> must write at least one byte: no protocol (other than the <see cref="MessageProtocol.ZeroProtocol"/>)
        /// is allowed to send empty messages.
        /// </summary>
        /// <param name="protocol">The protocol. Must be in the <see cref="AllowedProtocols"/>.</param>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A transport message.</returns>
        public TransportMessage Create( MessageProtocol protocol, Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( this, writer, minSequenceBufferSize, protocol );
        }

        /// <summary>
        /// Creates a static snapshot <see cref="TransportMessage"/>, its content is a single independent segment (not pooled).
        /// <see cref="TransportMessage.Dispose()"/> on a static message does nothing.
        /// </summary>
        /// <param name="protocol">The protocol. Must be in the <see cref="AllowedProtocols"/>.</param>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static transport message.</returns>
        public TransportMessage CreateStatic( MessageProtocol protocol, Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, writer, minSequenceBufferSize, protocol );
        }

        TransportMessage DoCreate( MessageFactory? factory, Action<IBufferWriter<byte>> writer, int minSequenceBufferSize, MessageProtocol protocol )
        {
            int protocolNumber = _allowed.GetProtocolNumber( protocol );
            // The "0 Protocol" message map is invalid. We use this here: only the "0 Protocol" can create its messages.
            if( protocolNumber < 0 || (protocolNumber == 0 && _allowed.IsValid) )
            {
                Throw.ArgumentException( $"Disallowed protocol '{protocolNumber}'. Allowed protocols are: {_allowed.Protocols.Select( p => p.ToString()).Concatenate()}." );
            }
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
                    if( protocolNumber != 0 ) Throw.InvalidOperationException( $"A TransportMessage cannot be empty (protocol '{protocol.Name}')." );
                    return TransportMessage.Empty;
                }
                Span<byte> prefix = stackalloc byte[_maxPrefixLength];
                prefixLength = WritePrefix( protocolNumber, messageLength, prefix );
                Debug.Assert( prefixLength <= _maxPrefixLength );
                int offset = _maxPrefixLength - prefixLength;
                prefix.Slice( 0, prefixLength ).CopyTo( header.Span.Slice( offset, prefixLength ) );
                if( factory == null )
                {
                    var content = new ReadOnlySequence<byte>( buffer.GetReadOnlySequence( offset ).ToArray() );
                    return new TransportMessage( protocol, content, prefixLength );
                }
                releaseBuffer = false;
                return new TransportMessage( factory, protocol, buffer, offset, prefixLength );
            }
            finally
            {
                if( releaseBuffer ) buffer.Dispose();
            }


            static int WritePrefix( int protocol, uint messageLength, Span<byte> memory )
            {
                Debug.Assert( memory.Length >= _maxPrefixLength );
                Debug.Assert( messageLength >= 0 && protocol < 64 );
                uint len = (uint)BitOperations.Log2( messageLength ) / 8;
                Debug.Assert( len >= 0 && len <= 3 );
                memory[0] = (byte)((len << 6) | (byte)protocol);
                if( !BitConverter.IsLittleEndian ) messageLength = BinaryPrimitives.ReverseEndianness( messageLength );
                Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( memory ), 1 ), messageLength );
                return (int)len + 2;
            }
        }
    }

}
