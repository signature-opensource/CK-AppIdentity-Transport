using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    struct OnionHeader
    {
        TODO;
    }

    /// <summary>
    /// Transport messages are simple length-prefixed block of bytes.
    /// The memory belongs to this message, disposing it releases the internal segments
    /// that compose the <see cref="WireMessage"/>: the ReadOnlySequence must no more be accessed
    /// once this message is disposed.
    /// <para>
    /// The maximal message length is <see cref="int.MaxValue"/> (2 GiB).
    /// </para>
    /// </summary>
    internal sealed class TransportMessageImpl : ITransportMessage, IDisposable, IIncomingMessage, IMessage
    {

        readonly MessageFactory? _messageFactory;
        readonly MutableSequence<byte>? _mutableSeq;
        readonly object? _disposeLock;
        object? _source;
        int _retainCount;
        private bool _isControl;
        private bool _isData;
        readonly MessageProtocol _protocol;
        readonly List<OnionHeader> _headers = new();

        // Constructor for the 4 special singleton messages.
        internal TransportMessageImpl( int emptyOrAck )
        {
            Debug.Assert( emptyOrAck >= 0 && emptyOrAck <= 2 );
            _protocol = MessageProtocol.ZeroProtocol;
        }

        // Constructor for static, non disposable, snapshot messages.
        internal TransportMessageImpl( MessageProtocol protocol, MutableSequence<byte> buffer )
        {
            _protocol = protocol;
            _mutableSeq = buffer;
        }

        // Constructor for regular, disposable messages.
        // offset skips the reserved bytes at the start that are unused by the prefixed length (short messages). 
        internal TransportMessageImpl( MessageFactory messageFactory, MessageProtocol protocol, MutableSequence<byte> buffer )
        {
            Debug.Assert( buffer.Length > 0 );
            _messageFactory = messageFactory;
            _mutableSeq = buffer;
            _protocol = protocol;
            _retainCount = 1;
            _disposeLock = new object();
        }

        public void AddHeader( OnionHeader header ) => _headers.Add( header );

        /// <inheritdoc />
        public bool IsValid => _isControl != _isData;

        /// <inheritdoc />
        public bool IsControl
        {
            get => _isControl;
            set
            {
                Throw.CheckState( IsValid );
                _isControl = value;
                _isData = !value;
            }
        }

        /// <inheritdoc />
        public bool IsData
        {
            get => _isData;
            set
            {
                Throw.CheckState( IsValid );
                _isData = value;
                _isControl = !value;
            }
        }

        /// <inheritdoc />
        public MessageProtocol Protocol => _protocol;

        /// <summary>
        /// Gets or sets an optional source object associated to this <see cref="TransportMessageImpl"/>.
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
                Throw.CheckState( IsValid );
                _source = value;
            }
        }

        /// <inheritdoc />
        public ReadOnlySequence<byte> Payload
        {
            get
            {
                Throw.CheckState( IsValid );
                return _mutableSeq?.GetReadOnlySequence() ?? ReadOnlySequence<byte>.Empty;
            }
        }

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
        public void Retain()
        {
            if( _disposeLock != null )
            {
                lock( _disposeLock )
                {
                    ++_retainCount;
                }
            }
        }

        /// <summary>
        /// Disposes this message.
        /// The <see cref="Invalid"/>, <see cref="Canceled"/>, <see cref="Empty"/> and <see cref="EmptyAck"/> messages ignore this,
        /// as well as messages created by the static <see cref="OutgoingMessageFactory.CreateStatic(Action{IBufferWriter{byte}}, int)"/>
        /// method.
        /// </summary>
        public void Dispose()
        {
            if( _disposeLock != null )
            {
                lock( _disposeLock )
                {
                    if( --_retainCount == 0 )
                    {
                        Debug.Assert( _mutableSeq != null && _messageFactory != null );
                        _messageFactory.Release( _mutableSeq );
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
