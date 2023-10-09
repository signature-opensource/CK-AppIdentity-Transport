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
        public OutgoingMessageBuilder CreateBuilder( int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var buffer = GetBuffer();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            return new OutgoingMessageBuilder( this, buffer );
        }

        /// <summary>
        /// Creates a message that must be <see cref="IRefCounted.Release"/> once done with it.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="isControl">True to set the <see cref="IOutgoingMessage.IsControl"/> bit.</param>
        /// <param name="source">Optional source of the message.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>An immutable message.</returns>
        public IOutgoingMessage Create( Action<MutableSequence<byte>> writer,
                                        bool isControl = false,
                                        object? source = null,
                                        int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var b = CreateBuilder( minSequenceBufferSize );
            try
            {
                b.Source = source;
                b.IsControl = isControl;
                var sequence = b.ObtainSequence();
                writer( sequence );
                return b.CreateMessage( sequence );
            }
            catch
            {
                b.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Creates a static snapshot <see cref="IOutgoingMessage"/>, its content is a single independent segment (not pooled).
        /// Disposing/releasing a static message does nothing.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is throw.</param>
        /// <param name="isControl">True to set the <see cref="IOutgoingMessage.IsControl"/> bit.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A static outgoing message.</returns>
        public IOutgoingMessage CreateStatic( Action<MutableSequence<byte>> writer,
                                              bool isControl = false,
                                              int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            var buffer = GetBuffer();
            buffer.MinimumBufferSize = minSequenceBufferSize;
            try
            {
                writer( buffer );
                if( buffer.Length > int.MaxValue ) Throw.InvalidOperationException( $"Buffered {buffer.Length} bytes exceeds {int.MaxValue} maximum message size." );
                return new StaticMessage( _protocol, isControl, buffer.GetReadOnlySequence().ToArray() );
            }
            finally
            {
                Release( buffer );
            }
        }

        sealed class StaticMessage : IOutgoingMessage
        {
            public StaticMessage( MessageProtocol protocol, bool isControl, byte[] content )
            {
                Protocol = protocol;
                IsControl = isControl;
                Message = new ReadOnlySequence<byte>( content );
            }

            public MessageProtocol Protocol { get; }

            public object? Source => null;

            public bool IsValid => true;

            public bool IsControl { get; }

            public bool IsData => !IsData;

            public ReadOnlySequence<byte> Message { get; }

            public void AddRef()
            {
            }

            public void Dispose()
            {
            }

            public void Release()
            {
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
