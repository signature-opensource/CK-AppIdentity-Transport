using CK.AppIdentity.TransportLayer.Message;
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
    /// Factory for outgoing <see cref="TransportMessageImpl"/>.
    /// There is only 2 ways to create an outgoing transport message:
    /// <list type="number">
    /// <item><see cref="Create(Action{IBufferWriter{byte}}, int)"/> for messages that must be disposed</item>
    /// <item><see cref="CreateStatic(Action{IBufferWriter{byte}}, int)"/> for messages that can be kept without the need to be disposed.</item>
    /// </list>
    /// <para>
    /// This class is thread safe.
    /// </para>
    /// </summary>
    public sealed class OutgoingMessageFactory : MessageFactory
    {
        readonly MessageProtocol _protocol;

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
        /// Creates a <see cref="TransportMessageImpl"/> by writing its content.
        /// The <paramref name="writer"/> must write at least one byte: no protocol (other than the "0 Protocol")
        /// is allowed to send empty messages.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="isControl">True to set the <see cref="TransportMessageImpl.IsControl"/> bit.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A transport message.</returns>
        public IMessage Create( Action<IBufferWriter<byte>> writer,
                                        bool isControl = false,
                                        int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( this, writer, null, isControl, minSequenceBufferSize );
        }

        /// <inheritdoc cref="Create(Action{IBufferWriter{byte}}, bool, int)"/>
        public IMessage Create( Action<MutableSequence<byte>> writer,
                                        bool isControl = false,
                                        int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( this, null, writer, isControl, minSequenceBufferSize );
        }

        /// <summary>
        /// Creates a static snapshot <see cref="TransportMessageImpl"/>, its content is a single independent segment (not pooled).
        /// <see cref="TransportMessageImpl.Dispose()"/> on a static message does nothing.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="isControl">True to set the <see cref="TransportMessageImpl.IsControl"/> bit.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static transport message.</returns>
        public IMessage CreateStatic( Action<IBufferWriter<byte>> writer,
                                              bool isControl = false,
                                              int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, writer, null, isControl, minSequenceBufferSize );
        }

        /// <inheritdoc cref="CreateStatic(Action{IBufferWriter{byte}}, bool, int)"/>
        public IMessage CreateStatic( Action<MutableSequence<byte>> writer,
                                              bool isControl = false,
                                              int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return DoCreate( null, null, writer, isControl, minSequenceBufferSize );
        }

        IMessage DoCreate( MessageFactory? factory,
                                   Action<IBufferWriter<byte>>? bufferwriter,
                                   Action<MutableSequence<byte>>? sequenceWriter,
                                   bool isControl,
                                   int minSequenceBufferSize )
        {
            Debug.Assert( (bufferwriter == null) != (sequenceWriter == null) );
            bool releaseBuffer = true;
            var payloadBuffer = GetBuffer();
            payloadBuffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                if( bufferwriter != null ) bufferwriter( payloadBuffer );
                else sequenceWriter!( payloadBuffer );

                var messageLength = payloadBuffer.Length;
                if( messageLength == 0 )
                {
                    Throw.InvalidOperationException( $"A TransportMessage cannot be empty (protocol '{_protocol.FullName}')." );
                }
                if( factory == null )
                {
                    return new StaticTransportMessageImpl( _protocol,
                                                          new ReadOnlySequence<byte>( payloadBuffer.GetReadOnlySequence().ToArray() ),
                                                          isControl );
                }
                releaseBuffer = false;
                return new TransportMessageImpl( factory, _protocol, payloadBuffer );
            }
            finally
            {
                if( releaseBuffer ) Release( payloadBuffer );
            }
        }
    }

}
