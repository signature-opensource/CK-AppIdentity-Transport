using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Incoming messages are simple length-prefixed block of bytes.
    /// The memory belongs to this message, disposing it releases the internal segments
    /// that compose the <see cref="WireMessage"/>: the ReadOnlySequence must no more be accessed
    /// once this message is disposed.
    /// <para>
    /// The maximal message length is <see cref="int.MaxValue"/> (2 GiB).
    /// </para>
    /// </summary>
    public sealed class IncomingMessage : IRefCounted, IDisposable
    {
        internal const int IsControlFlag = 0b00100000;

        readonly IncomingMessageFactory? _messageFactory;
        readonly MutableSequence<byte>? _buffer;
        readonly ReadOnlySequence<byte> _wireMessage;
        readonly ReadOnlySequence<byte> _message;
        readonly MessageProtocol _protocol;
        int _refCount;

        /// <summary>
        /// A purely invalid message singleton. It can be safely disposed and will remain invalid.
        /// <see cref="Canceled"/> is also invalid but conveys a cancellation of the process.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IncomingMessage Invalid = new IncomingMessage( 0 );

        /// <summary>
        /// A canceled message singleton is invalid. It can be safely disposed and will remain invalid.
        /// <para>
        /// Its protocol is the "0 Protocol".
        /// </para>
        /// </summary>
        public static readonly IncomingMessage Canceled = new IncomingMessage( 0 );

        /// <summary>
        /// The "0 Protocol" empty message singleton is a 0 byte prefixed message (2 bytes on the wire).
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IncomingMessage Empty = new IncomingMessage( 1 );

        /// <summary>
        /// The "0 Protocol" empty acknowledgment message singleton (2 bytes on the wire) with
        /// <see cref="IncomingMessage.IsResponse"/> set.
        /// It can be safely disposed and will remain valid and empty.
        /// </summary>
        public static readonly IncomingMessage EmptyAck = new IncomingMessage( 2 );

        // Constructor for the 4 special singleton messages.
        IncomingMessage( int emptyOrAck )
        {
            Debug.Assert( emptyOrAck >= 0 && emptyOrAck <= 2 );
            _protocol = MessageProtocol.ZeroProtocol;
            if( emptyOrAck != 0 )
            {
                _wireMessage = new ReadOnlySequence<byte>( new byte[] { (byte)(emptyOrAck == 1 ? 0 : OutgoingMessage.IsControlFlag), 0 } );
            }
            Debug.Assert( _message.IsEmpty );
        }

        // Constructor for regular, disposable messages.
        internal IncomingMessage( IncomingMessageFactory messageFactory,
                                  MessageProtocol protocol,
                                  MutableSequence<byte> buffer,
                                  int prefixLength )
        {
            Debug.Assert( messageFactory != null && buffer != null && prefixLength > 0 && buffer.Length > 0 );
            Debug.Assert( prefixLength >= 2 && prefixLength <= OutgoingMessage.MaxPrefixLength );
            _messageFactory = messageFactory;
            _buffer = buffer;
            _protocol = protocol;
            _wireMessage = buffer.GetReadOnlySequence();
            _message =  _wireMessage.Slice( prefixLength );
            _refCount = 1;
        }

        /// <summary>
        /// Gets whether this message is valid: it is not the <see cref="Invalid"/> nor the <see cref="Canceled"/> message
        /// and has not been disposed yet.
        /// </summary>
        public bool IsValid => _refCount != 0 && !_wireMessage.IsEmpty;

        /// <summary>
        /// Gets whether this message is a valid control message.
        /// </summary>
        public bool IsControl => IsValid ? (_wireMessage.FirstSpan[0] & OutgoingMessage.IsControlFlag) != 0 : false;

        /// <summary>
        /// Gets whether this message is a valid data message.
        /// </summary>
        public bool IsData => IsValid ? (_wireMessage.FirstSpan[0] & OutgoingMessage.IsControlFlag) == 0 : false;

        /// <summary>
        /// Gets the message protocol.
        /// </summary>
        public MessageProtocol Protocol => _protocol;

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
                return _message;
            }
        }

        internal int GetProtocolNumber()
        {
            Debug.Assert( IsValid );
            return _wireMessage.First.Span[0] & 7;
        }

        /// <summary>
        /// Retains this message, preventing a <see cref="Release()"/> to release the resources.
        /// Release must be called as many times as AddRef has been called for the resources to be released.
        /// Calling this on the special messages <see cref="Invalid"/>, <see cref="Canceled"/>, <see cref="Empty"/> and <see cref="EmptyAck"/>
        /// or a static message (see <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/> )
        /// has no effect and returns false.
        /// </summary>
        public void AddRef()
        {
            if( _refCount != 0 )
            {
                Debug.Assert( _buffer != null );
                lock( _buffer )
                {
                    if( _refCount != 0 )
                    {
                        ++_refCount;
                    }
                }
            }
        }

        /// <summary>
        /// Releases this message.
        /// The <see cref="Invalid"/>, <see cref="Canceled"/>, <see cref="Empty"/> and <see cref="EmptyAck"/> messages ignore this.
        /// </summary>
        public void Release()
        {
            if( _refCount != 0 )
            {
                Debug.Assert( _buffer != null );
                lock( _buffer )
                {
                    if( _refCount != 0 && --_refCount == 0 )
                    {
                        Debug.Assert( _messageFactory != null );
                        _messageFactory.Release( _buffer );
                    }
                }
            }
        }

        /// <summary>
        /// Synonym of <see cref="Release"/>.
        /// </summary>
        public void Dispose() => Release();
    }
}
