using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Reflection.Emit;

namespace CK.AppIdentity.PocoChannel
{
    abstract class Transport
    {
        readonly ConnectionManager _connectionManager;
        readonly IListener? _listener;
        DateTime _lastReceived;
        readonly BufferEditorFactory _receiveBufferFactory;
        readonly AsyncLock _sendLock;

        BufferEditorFactory.Buffer? _emptyReadyBuffer;
        int _receivingFlag;

        protected Transport( ConnectionManager connectionManager, IListener? source )
        {
            _connectionManager = connectionManager;
            _listener = source;
            _lastReceived = DateTime.UtcNow;
            _receiveBufferFactory = new BufferEditorFactory();
            _sendLock = new AsyncLock( LockRecursionPolicy.NoRecursion );
        }

        public IListener? Listener => _listener;

        public DateTime LastReceivedTime => _lastReceived;


        /// <summary>
        /// Must handle the full <paramref name="buffer"/>.
        /// Calls to this methods are serialized.
        /// </summary>
        /// <param name="buffer">The buffer to send.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected abstract ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default );

        /// <summary>
        /// Must read the incoming available data and return the number of bytes read.
        /// </summary>
        /// <param name="buffer">The buffer to fill with the read data.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>The number of bytes actually read.</returns>
        protected abstract ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellationToken = default );


        /// <summary>
        /// Sends a <see cref="ReadOnlySequence{T}"/> of bytes. Default implementation simply calls
        /// <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> of each sequence (in
        /// a <see cref="EnterSendAsync(IActivityMonitor)"/>/<see cref="LeaveSend(IActivityMonitor)"/> region).
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="buffer">The multiple buffers to send.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected virtual async ValueTask SendAsync( IActivityMonitor monitor, ReadOnlySequence<byte> buffer, CancellationToken cancellationToken = default )
        {
            await EnterSendAsync( monitor, cancellationToken );
            try
            {
                foreach( var part in buffer )
                {
                    await SendAsync( part, cancellationToken ).ConfigureAwait( false );
                }
            }
            finally
            {
                LeaveSend( monitor );
            }
        }

        /// <summary>
        /// Sends a <see cref="TransportMessage"/> that must be <see cref="TransportMessage.IsValid"/> otherwise
        /// an <see cref="ArgumentException"/> is thrown.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="message">The valid message to send.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>The awaitable.</returns>
        public ValueTask SendAsync( IActivityMonitor monitor, TransportMessage message, CancellationToken cancellationToken = default )
        {
            Throw.CheckArgument( message != null && message.IsValid );
            return SendAsync( monitor, message.PrefixedMessage, cancellationToken );
        }

        /// <summary>
        /// Must be called before sending. <see cref="LeaveSend(IActivityMonitor)"/> must be called, typically from a finally block.
        /// </summary>
        /// <param name="monitor">The monitor used to handle the <see cref="AsyncLock"/>.</param>
        /// <param name="cancellation">The cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected Task EnterSendAsync( IActivityMonitor monitor, CancellationToken cancellation ) => _sendLock.EnterAsync( monitor, cancellation );

        /// <summary>
        /// Leaves the <see cref="AsyncLock"/> acquired by <see cref="EnterSendAsync(IActivityMonitor, CancellationToken)"/>.
        /// </summary>
        /// <param name="monitor">The monitor used to handle the <see cref="AsyncLock"/>.</param>
        protected void LeaveSend( IActivityMonitor monitor ) => _sendLock.Leave( monitor );


        /// <summary>
        /// Read a <see cref="TransportMessage"/> from this transport.
        /// The message may not be <see cref="Transport.IsValid"/> if a received message is bigger than <paramref name="maxMassageLength"/>.
        /// When valid, it MUST be disposed once done with it.
        /// </summary>
        /// <param name="maxMassageLength">The maximal message length.</param>
        /// <param name="cancellation">Optional cancellation token.</param>
        /// <returns>The message. If the received message is longer than <paramref name="maxMassageLength"/> then <see cref="TransportMessage.IsValid"/> is false.</returns>
        public async ValueTask<TransportMessage> ReadAsync( int maxMassageLength = int.MaxValue, CancellationToken cancellation = default )
        {
            if( Interlocked.CompareExchange( ref _receivingFlag, 1, 0 ) == 1 ) Throw.InvalidOperationException( "ReadAsync is already executing." );
            try
            {
                BufferEditorFactory.Buffer? buffer = Interlocked.Exchange( ref _emptyReadyBuffer, null );
                buffer ??= _receiveBufferFactory.CreateBuffer();

                var header = buffer.GetMemory();
                Debug.Assert( header.Length > 8, "BufferEditorFactoryOptions.DefaultMinimumBufferSize cannot be smaller than 16." );

                retryHeader:
                Debug.Assert( buffer.Length == 0 );
                if( await ReadExactlyAsync( header.Slice( 0, 1 ), cancellation ).ConfigureAwait( false ) )
                {
                    // Update lastReceived. This updates keep alive for this remote.
                    _lastReceived = DateTime.UtcNow;
                    byte len = header.Span[0];
                    if( len == 0 )
                    {
                        // A single 0 byte is not a TransportMessage, it is the keep alive: the other side worries
                        // about us because we did not send it any message for some time. Let's reassure it if we are not
                        // currently sending it anything.
                        if( !_sendLock.IsEntered )
                        {
                            _connectionManager.OnKeepAliveReceived( this );
                        }
                        goto retryHeader;
                    }
                    buffer.Advance( 1 );
                    if( len < 128 )
                    {
                        var content = buffer.GetMemory( len );
                        if( await ReadExactlyAsync( content.Slice( 0, len ), cancellation ).ConfigureAwait( false ) )
                        {
                            return new TransportMessage( _receiveBufferFactory, buffer, 1 );
                        }
                    }
                    // This protocol cannot exchange a single byte since a message is always prefixed by its length.
                    if( await ReadExactlyAsync( header.Slice( 0, 2 ), cancellation ).ConfigureAwait( false ) )
                {
                    if( header.Span[0] < 0x7Fu )
                    {
                        // 
                    }
                    int mLength = BitConverter.ToUInt16( header.AsSpan( 0, 2 ) );
                    if( await ReadExactlyAsync( buffer.AsMemory( 2 ), cancellation ).ConfigureAwait( false ) )
                    {
                        return new IncomingShortMessage( buffer, mLength );
                    }
                }
            }
            catch
            {
                buffer.Dispose();
                throw;
            }
            finally
            {
                Interlocked.Exchange( ref _receivingFlag, 0 );
            }
        }

        async ValueTask<bool> ReadExactlyAsync( Memory<byte> buffer, CancellationToken cancellation )
        {
            Memory<byte> readBuffer = buffer;
            for( ; ; )
            {
                int len = await ReceiveAsync( readBuffer, cancellation ).ConfigureAwait( false );
                if( len <= 0 ) return false;
                if( len == readBuffer.Length ) return true;
            }
        }
    }
}
