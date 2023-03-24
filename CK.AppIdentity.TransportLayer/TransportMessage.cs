using CK.Core;
using System.Buffers;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Transport messages are simple length-prefixed block of bytes.
    /// The memory belongs to this message, disposing it releases the internal segments
    /// that compose the <see cref="WireMessage"/>: the ReadOnlySequence must no more be accessed
    /// once this message is disposed.
    /// <para>
    /// The maximal total message length is <see cref="int.MaxValue"/> - 6 (2 GiB minus the maximal prefix length that is 6 bytes).
    /// </para>
    /// </summary>
    public sealed class TransportMessage : IDisposable
    {
        readonly MessageFactory? _messageFactory;
        readonly MutableSequence<byte>? _buffer;
        readonly ReadOnlySequence<byte> _wireMessage;
        readonly object? _disposeLock;
        int _prefixLength;
        int _retainCount;
        byte _protocolNumber;

        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// <para>
        /// Its protocol number is the "0" protocol.
        /// </para>
        /// </summary>
        public static readonly TransportMessage Invalid = new TransportMessage( false );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// <para>
        /// Its protocol number is the "0" protocol.
        /// </para>
        /// </summary>
        public static readonly TransportMessage Canceled = new TransportMessage( false );

        /// <summary>
        /// The empty message singleton is a 0 byte prefixed message.
        /// It can be safely disposed and will remain valid and empty.
        /// <para>
        /// Its protocol number is the "0" protocol.
        /// </para>
        /// </summary>
        public static readonly TransportMessage Empty = new TransportMessage( true );

        // Constructor for the 3 special singleton messages.
        TransportMessage( bool empty )
        {
            if( empty )
            {
                _prefixLength = 2;
                _wireMessage = new ReadOnlySequence<byte>( new byte[] { 0, 0 } );
            }
        }

        // Constructor for regular, disposable messages.
        // offset skips the reserved bytes at the start that are unused by the prefixed length (short messages). 
        internal TransportMessage( MessageFactory messageFactory, byte protocolNumber, MutableSequence<byte> buffer, int offset, int prefixLength )
        {
            Debug.Assert( messageFactory != null && prefixLength > 0 && buffer.Length > 0 );
            Debug.Assert( prefixLength >= 2 && prefixLength <= MessageFactory._maxPrefixLength );
            _messageFactory = messageFactory;
            _buffer = buffer;
            _prefixLength = prefixLength;
            _protocolNumber = protocolNumber;
            _wireMessage = buffer.GetReadOnlySequence( offset );
            _retainCount = 1;
            _disposeLock = new object();
        }

        // Constructor for static, non disposable, snapshot messages.
        internal TransportMessage( byte protocolNumber, ReadOnlySequence<byte> prefixedMessage, int prefixLength )
        {
            Debug.Assert( prefixedMessage.IsSingleSegment && !prefixedMessage.IsSingleSegment );
            Debug.Assert( prefixLength >= 2 && prefixLength <= MessageFactory._maxPrefixLength );
            _protocolNumber = protocolNumber;
            _prefixLength = prefixLength;
            _wireMessage = prefixedMessage;
        }

        /// <summary>
        /// Gets whether this message is valid: it is not the <see cref="Invalid"/> nor the <see cref="Canceled"/> message
        /// and has not been disposed yet.
        /// </summary>
        public bool IsValid => _prefixLength != 0;

        /// <summary>
        /// Gets the protocol number.
        /// The "0" protocol is the reserved system protocol.
        /// </summary>
        public byte ProtocolNumber => _protocolNumber;

        /// <summary>
        /// Gets the full message including its prefix.
        /// <see cref="IsValid"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        public ReadOnlySequence<byte> WireMessage
        {
            get
            {
                Throw.CheckState( IsValid );
                return _wireMessage;
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
                return _wireMessage.Slice( _prefixLength );
            }
        }

        /// <summary>
        /// Retains this message, preventing a <see cref="Dispose()"/> to release the resources.
        /// Dispose must be called as many times as Retain has been called for the resources to be released.
        /// Calling this on the special messages <see cref="Invalid"/>, <see cref="Canceled"/> and <see cref="Empty"/>
        /// or a static message (see <see cref="Protocol0MessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/> )
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
        /// as well as messages created by the static <see cref="Protocol0MessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/>
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
