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
    /// The maximal total message length is <see cref="int.MaxValue"/> (2 GiB).
    /// </para>
    /// </summary>
    public sealed class TransportMessage : ITransportMessage, IDisposable
    {
        internal const int IsControlFlag = 0b00100000;

        readonly MessageFactory? _messageFactory;
        readonly int _protocolNumber;
        readonly MutableSequence<byte>? _buffer;
        readonly ReadOnlySequence<byte> _wireMessage;
        readonly object? _disposeLock;
        object? _source;
        int _prefixLength;
        int _retainCount;
        readonly MessageProtocol _protocol;

        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly TransportMessage Invalid = new TransportMessage( 0 );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly TransportMessage Canceled = new TransportMessage( 0 );

        /// <summary>
        /// The "0 Protocol" empty message singleton is a 0 byte prefixed message (2 bytes on the wire).
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly TransportMessage Empty = new TransportMessage( 1 );

        /// <summary>
        /// The "0 Protocol" empty acknowledgment message singleton (2 bytes on the wire) with
        /// <see cref="TransportMessage.IsControl"/> set.
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly TransportMessage EmptyAck = new TransportMessage( 2 );

        // Constructor for the 4 special singleton messages.
        TransportMessage( int emptyOrAck )
        {
            Debug.Assert( emptyOrAck >= 0 && emptyOrAck <= 2 );
            _protocol = MessageProtocol.ZeroProtocol;
            if( emptyOrAck != 0 )
            {
                _prefixLength = 2;
                _wireMessage = new ReadOnlySequence<byte>( new byte[] { (byte)(emptyOrAck == 1 ? 0 : 0b0010000), 0 } );
            }
        }

        // Constructor for regular, disposable messages.
        // offset skips the reserved bytes at the start that are unused by the prefixed length (short messages). 
        internal TransportMessage( MessageFactory messageFactory, int protocolNumber, MessageProtocol protocol, MutableSequence<byte> buffer, int offset, int prefixLength )
        {
            Debug.Assert( messageFactory != null && prefixLength > 0 && buffer.Length > 0 );
            Debug.Assert( prefixLength >= 2 && prefixLength <= MessageFactory._maxPrefixLength );
            _messageFactory = messageFactory;
            _protocolNumber = protocolNumber;
            _buffer = buffer;
            _prefixLength = prefixLength;
            _protocol = protocol;
            _wireMessage = buffer.GetReadOnlySequence( offset );
            _retainCount = 1;
            _disposeLock = new object();
        }

        // Constructor for static, non disposable, snapshot messages.
        internal TransportMessage( int protocolNumber, MessageProtocol protocol, ReadOnlySequence<byte> prefixedMessage, int prefixLength )
        {
            Debug.Assert( prefixedMessage.IsSingleSegment && !prefixedMessage.IsSingleSegment );
            Debug.Assert( prefixLength >= 2 && prefixLength <= MessageFactory._maxPrefixLength );
            _protocolNumber = protocolNumber;
            _protocol = protocol;
            _prefixLength = prefixLength;
            _wireMessage = prefixedMessage;
        }

        /// <inheritdoc />
        public bool IsValid => _prefixLength != 0;

        /// <inheritdoc />
        public bool IsControl => _prefixLength != 0 ? (_wireMessage.FirstSpan[0] & IsControlFlag) != 0 : false;

        /// <inheritdoc />
        public bool IsData => _prefixLength != 0 ? (_wireMessage.FirstSpan[0] & IsControlFlag) == 0 : false;

        /// <inheritdoc />
        public MessageProtocol Protocol => _protocol;

        /// <summary>
        /// Gets or sets an optional source object associated to this <see cref="TransportMessage"/>.
        /// For an outgoing message, this typically references a data object that is serialized in the message.
        /// <para>
        /// When this object is <see cref="IDisposable"/>, it is automatically disposed when this message
        /// is disposed.
        /// </para>
        /// </summary>
        public object? Source
        {
            get => _source;
            set
            {
                Throw.CheckState( IsValid && this != Empty );
                _source = value;
            }
        }

        /// <inheritdoc />
        public ReadOnlySequence<byte> WireMessage
        {
            get
            {
                Throw.CheckState( IsValid );
                return _wireMessage;
            }
        }

        /// <inheritdoc />
        public ReadOnlySequence<byte> Message
        {
            get
            {
                Throw.CheckState( IsValid );
                return _wireMessage.Slice( _prefixLength );
            }
        }

        /// <summary>
        /// Gets the protocol number in the protocol map that has been used to create this message.
        /// This has absolutely no reason to be made public.
        /// </summary>
        internal int ProtocolNumber => _protocolNumber;

        /// <summary>
        /// Retains this message, preventing a <see cref="Dispose()"/> to release the resources.
        /// Dispose must be called as many times as Retain has been called for the resources to be released.
        /// Calling this on the special messages <see cref="Invalid"/>, <see cref="Canceled"/>, <see cref="Empty"/> and <see cref="EmptyAck"/>
        /// or a static message (see <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/> )
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
        /// The <see cref="Invalid"/>, <see cref="Canceled"/>, <see cref="Empty"/> and <see cref="EmptyAck"/> messages ignore this,
        /// as well as messages created by the static <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/>
        /// method.
        /// </summary>
        public void Dispose()
        {
            if( _disposeLock != null && _prefixLength != 0 )
            {
                lock( _disposeLock )
                {
                    if( _prefixLength != 0 && --_retainCount == 0 )
                    {
                        _prefixLength = 0;
                        Debug.Assert( _buffer != null && _messageFactory != null );
                        _messageFactory.Release( _buffer );
                        if( _source is IDisposable s )
                        {
                            try
                            {
                                s.Dispose();
                            }
                            catch( Exception e )
                            {
                                ActivityMonitor.StaticLogger.Error( "While disposing Source object of a TransportMessage.", e );
                            }
                        }
                    }
                }
            }
        }
    }
}
