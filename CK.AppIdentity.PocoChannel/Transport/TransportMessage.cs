using CK.Core;
using System.Buffers;
using System.Diagnostics;

namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Transport messages are simple length-prefixed bytes.
    /// The memory belongs to this message, disposing it releases the internal segments
    /// that compose the <see cref="PrefixedMessage"/>: the ReadOnlySequence must no more be accessed
    /// once this message is disposed.
    /// </summary>
    public sealed class TransportMessage : IDisposable
    {
        readonly TransportMessageFactory _messageFactory;
        readonly BufferEditorFactory.Buffer _buffer;
        readonly ReadOnlySequence<byte> _prefixedMessage;
        int _prefixLength;

        internal TransportMessage( TransportMessageFactory messageFactory, BufferEditorFactory.Buffer buffer, int prefixLength )
        {
            Debug.Assert( prefixLength > 0 );
            _messageFactory = messageFactory;
            _buffer = buffer;
            _prefixLength = prefixLength;
            _prefixedMessage = buffer.GetReadOnlySequence();
        }

        /// <summary>
        /// Gets whether this message is valid.
        /// It can be invalid from the start (for example when a received message exceeds a maximal allowed size) or
        /// once <see cref="Dispose()"/> has been called.
        /// </summary>
        public bool IsValid => _prefixLength != 0;

        /// <summary>
        /// Gets the full message including its length prefix.
        /// <see cref="IsValid"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        public ReadOnlySequence<byte> PrefixedMessage
        {
            get
            {
                Throw.CheckState( IsValid );
                return _prefixedMessage;
            }
        }

        /// <summary>
        /// Gets the message.
        /// <see cref="IsValid"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        public ReadOnlySequence<byte> Message
        {
            get
            {
                Throw.CheckState( IsValid );
                return _prefixedMessage.Slice( _prefixLength );
            }
        }

        /// <summary>
        /// Dispose this message.
        /// </summary>
        public void Dispose()
        {
            if( Interlocked.Exchange( ref _prefixLength, 0 ) != 0 )
            {
                _messageFactory.Release( _buffer );
            }
        }
    }
}
