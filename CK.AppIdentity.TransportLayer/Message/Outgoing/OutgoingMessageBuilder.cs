using CK.Core;
using CommunityToolkit.HighPerformance.Buffers;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Threading;

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
        MutableSequence<byte>? _sequence;
        object? _source;
        int _state;
        bool _isControl;

        internal OutgoingMessageBuilder( OutgoingMessageFactory messageFactory, MutableSequence<byte> buffer )
        {
            _messageFactory = messageFactory;
            _sequence = _buffer = buffer;
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
        /// Obtains the mutable sequence that is a <see cref="IBufferWriter{T}"/>.
        /// <see cref="ReleaseSequence"/> must be called.
        /// </summary>
        /// <returns>The mutable sequence.</returns>
        public MutableSequence<byte> ObtainSequence()
        {
            Throw.CheckState( !IsDisposed );
            var sequence = Interlocked.Exchange( ref _sequence, null );
            Throw.CheckState( sequence != null );
            return sequence;
        }

        /// <summary>
        /// Releases the sequence obtained by <see cref="ObtainSequence"/>.
        /// </summary>
        /// <param name="sequence">The sequence to release.</param>
        public void ReleaseSequence( MutableSequence<byte> sequence )
        {
            Throw.CheckArgument( sequence == _buffer );
            var anotherReleased = Interlocked.CompareExchange( ref _sequence, sequence, null );
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
        /// Releases the previously obtained sequence, creates an immutable message and disposes this builder.
        /// This can be called once and only once and only if at least one byte has been written to the
        /// sequence (thanks to <see cref="ObtainSequence"/>).
        /// </summary>
        /// <param name="sequence">The writer previously obtained by <see cref="ObtainSequence"/>.</param>
        public IOutgoingMessage CreateMessage( MutableSequence<byte> sequence )
        {
            Throw.CheckArgument( sequence == _buffer && _sequence == null );
            if( sequence.Length == 0 )
            {
                Throw.InvalidOperationException( "No data has been written to the outgoing message." );
            }
            if( sequence.Length > int.MaxValue )
            {
                Throw.InvalidOperationException( $"Buffered {sequence.Length} bytes exceeds {int.MaxValue} maximum message size." );
            }
            // We have a unique access to the buffer. We can easily detect that Dispose has
            // been called (and the buffer should not be used).
            if( Interlocked.Exchange( ref _state, 1 ) != 0 )
            {
                Throw.ObjectDisposedException();
            }
            // Unique access to the non disposed buffer is now guaranteed.
            // We let this builder in its "disposed" state and with its the writer "unreleased".
            return new OutgoingMessage( _messageFactory, sequence, _source, _isControl );
        }

        /// <summary>
        /// Creates an immutable message and dispose this builder.
        /// This can be called once and only once and only if at least one byte has been written to the internal writer (thanks to <see cref="ObtainSequence"/>).
        /// </summary>
        public IOutgoingMessage CreateMessage()
        {
            // By obtaining the buffer, we preserve any future change and
            // if the writer has not been released, then this fails.
            var buffer = ObtainSequence();
            if( buffer.Length == 0 )
            {
                ReleaseSequence( buffer );
                Throw.InvalidOperationException( "No data has been written to the outgoing message." );
            }
            if( buffer.Length > int.MaxValue )
            {
                ReleaseSequence( buffer );
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
