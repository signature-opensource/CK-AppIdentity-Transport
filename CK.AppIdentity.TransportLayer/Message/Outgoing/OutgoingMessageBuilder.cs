using CK.Core;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// <see cref="IOutgoingMessage"/> builder.
    /// </summary>
    public sealed partial class OutgoingMessageBuilder: IDisposable
    {
        internal const int IsControlFlag = 0b00100000;

        readonly OutgoingMessageFactory _messageFactory;
        readonly MutableSequence<byte> _buffer;
        MutableSequence<byte>? _writer;
        object? _source;
        int _state;
        bool _isControl;

        internal OutgoingMessageBuilder( OutgoingMessageFactory messageFactory, MutableSequence<byte> buffer )
        {
            _messageFactory = messageFactory;
            _buffer = buffer;
        }

        /// <summary>
        /// Gets the message protocol.
        /// </summary>
        public MessageProtocol Protocol => _messageFactory.Protocol;

        /// <summary>
        /// Gets or sets whether this message is a control message.
        /// </summary>
        public bool IsControl
        {
            get => _isControl;
            set
            {
                Throw.CheckState( !IsDisposed );
                _isControl = value;
            }
        }

        /// <summary>
        /// Gets or sets whether this message is a data message.
        /// </summary>
        public bool IsData
        {
            get => !_isControl;
            set
            {
                Throw.CheckState( !IsDisposed );
                _isControl = !value;
            }
        }

        /// <summary>
        /// Gets or sets an optional source object associated to this <see cref="OutgoingMessageBuilder"/>.
        /// This typically references a data object that is serialized in the message.
        /// </summary>
        public object? Source
        {
            get => _source;
            set
            {
                Throw.CheckState( !IsDisposed );
                _source = value;
            }
        }

        /// <summary>
        /// Gets the message.
        /// </summary>
        public ReadOnlySequence<byte> Message
        {
            get
            {
                Throw.CheckState( !IsDisposed );
                return _buffer.GetReadOnlySequence();
            }
        }

        /// <summary>
        /// Obtains the mutable sequence that is a buffer writer.
        /// <see cref="ReleaseWriter"/> must be called.
        /// </summary>
        /// <returns></returns>
        public MutableSequence<byte> ObtainWriter()
        {
            Throw.CheckState( !IsDisposed );
            var writer = Interlocked.Exchange( ref _writer, null );
            Throw.CheckState( writer != null );
            return writer;
        }

        /// <summary>
        /// Releases the writer obtained by <see cref="ObtainWriter"/>.
        /// </summary>
        /// <param name="writer">The writer to release.</param>
        public void ReleaseWriter( MutableSequence<byte> writer )
        {
            Throw.CheckArgument( writer == _buffer );
            var anotherReleased = Interlocked.CompareExchange( ref _writer, writer, null );
            Throw.CheckState( anotherReleased == null );
        }

        /// <summary>
        /// Gets whether this builder has been disposed.
        /// </summary>
        public bool IsDisposed => _state != 0;

        /// <summary>
        /// Disposes this builder. <see cref="CreateMessage()"/> cannot be called anymore.
        /// </summary>
        public void Dispose()
        {
            if( Interlocked.CompareExchange( ref _state, 1, 0 ) == 0 )
            {
                _messageFactory.Release( _buffer );
            }
        }

        /// <summary>
        /// Creates an immutable message. This can be called once and only once and only
        /// if at least one byte has been written to the internal writer (thanks to <see cref="ObtainWriter"/>).
        /// </summary>
        public IOutgoingMessage CreateMessage()
        {
            // By obtaining the buffer, we preserve any future change and
            // if the writer has not been released, then this fails.
            var buffer = ObtainWriter();
            if( buffer.Length == 0 )
            {
                ReleaseWriter( buffer );
                Throw.InvalidOperationException( "No data has been written to the outgoing message." );
            }
            if( buffer.Length > int.MaxValue )
            {
                ReleaseWriter( buffer );
                Throw.InvalidOperationException( $"Buffered {buffer.Length} bytes exceeds {int.MaxValue} maximum message size." );
            }
            // We have a unique access to the buffer. We can easily detect that Dispose has
            // been called (and the buffer should not be used).
            if( Interlocked.Exchange( ref _state, 1 ) != 0 )
            {
                Throw.ObjectDisposedException();
            }
            // Unique access to the non disposed buffer is now guaranteed.
            // We let this builder in its "disposed" state and with its the writer "unreleased".
            return new OutgoingMessage( _messageFactory, buffer, _source, _isControl );
        }

    }
}
