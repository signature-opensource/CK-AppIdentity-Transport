using CK.Core;
using System.Buffers;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Transport messages are simple length-prefixed block of bytes.
    /// The memory belongs to this message, disposing it releases the internal segments
    /// that compose the <see cref="PrefixedMessage"/>: the ReadOnlySequence must no more be accessed
    /// once this message is disposed.
    /// <para>
    /// The maximal message length is <see cref="int.MaxValue"/> (2 GiB).
    /// </para>
    /// </summary>
    public sealed class TransportMessage : IDisposable
    {
        readonly TransportMessageFactory? _messageFactory;
        readonly MutableSequence<byte>? _buffer;
        readonly ReadOnlySequence<byte> _prefixedMessage;
        int _prefixLength;
        int _retainCount;
        readonly object? _disposeLock;

        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// </summary>
        public static readonly TransportMessage Invalid = new TransportMessage( false );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// </summary>
        public static readonly TransportMessage Canceled = new TransportMessage( false );

        /// <summary>
        /// The empty message singleton is a 0 byte prefixed message.
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly TransportMessage Empty = new TransportMessage( true );

        // Constructor for the 3 special singleton messages.
        TransportMessage( bool empty )
        {
            if( empty )
            {
                _prefixLength = 1;
                _prefixedMessage = new ReadOnlySequence<byte>( new byte[] { 0 } );
            }
        }

        // Constructor for regular, disposable messages.
        // offset skips the reserved bytes at the start that are unused by the prefixed length (short messages). 
        internal TransportMessage( TransportMessageFactory messageFactory, MutableSequence<byte> buffer, int offset, int prefixLength )
        {
            Debug.Assert( messageFactory != null && prefixLength > 0 && buffer.Length > 0 );
            Debug.Assert( prefixLength > 0 && prefixLength <= TransportMessageFactory._maxPrefixLength );
            _messageFactory = messageFactory;
            _buffer = buffer;
            _prefixLength = prefixLength;
            _prefixedMessage = buffer.GetReadOnlySequence( offset );
            _retainCount = 1;
            _disposeLock = new object();
        }

        // Constructor for static, non disposable, snapshot messages.
        internal TransportMessage( ReadOnlySequence<byte> prefixedMessage, int prefixLength )
        {
            Debug.Assert( prefixedMessage.IsSingleSegment && !prefixedMessage.IsSingleSegment );
            Debug.Assert( prefixLength > 0 && prefixLength <= TransportMessageFactory._maxPrefixLength );
            _prefixLength = prefixLength;
            _prefixedMessage = prefixedMessage;
        }

        /// <summary>
        /// Gets whether this message is valid: it is not the <see cref="Invalid"/> nor the <see cref="Canceled"/> message
        /// and has not been disposed yet.
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
        /// Retains this message, preventing a <see cref="Dispose()"/> to release the resources.
        /// Dispose must be called as many times as Retain has been called for the resources to be released.
        /// Calling this on the special messages <see cref="Invalid"/>, <see cref="Canceled"/> and <see cref="Empty"/>
        /// or a static message (see <see cref="TransportMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/> )
        /// has no effect and returns false.
        /// </summary>
        /// <returns>
        /// True if the message has been retained and <see cref="Dispose()"/> must be called.
        /// False if it is already Disposed, if this is one of the special messages or is a static message.
        /// </returns>
        public bool Retain()
        {
            if( _disposeLock != null && _prefixLength != 0 )
            {
                lock( _disposeLock )
                {
                    if( _prefixLength != 0 )
                    {
                        ++_retainCount;
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Disposes this message.
        /// The <see cref="Invalid"/>, <see cref="Canceled"/> and <see cref="Empty"/> messages ignore this,
        /// as well as messages created by the static <see cref="TransportMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/>
        /// method.
        /// </summary>
        public void Dispose()
        {
            if( _disposeLock != null && _prefixLength != 0 )
            {
                lock( _disposeLock)
                {
                    if( _prefixLength != 0 && --_retainCount == 0 )
                    {
                        _prefixLength = 0;
                        Debug.Assert( _buffer != null && _messageFactory != null );
                        _messageFactory.Release( _buffer );
                    }
                }
            }
        }
    }
}
