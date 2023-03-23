using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Reflection.Emit;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// A Transport is able to send and receive <see cref="TransportMessage"/>.
    /// Concrete implementations can be <see cref="IAsyncDisposable"/> or <see cref="IDisposable"/>:
    /// the connection manager will prefer <see cref="IAsyncDisposable"/> and will call the latter otherwise.
    /// </summary>
    public abstract class Transport : ITransport
    {
        readonly TransportListener? _listener;
        readonly SemaphoreSlim? _sendLock;
        readonly TransportMessageFactory _receiveFactory;
        readonly Func<Memory<byte>, CancellationToken, ValueTask> _reader;
        readonly string _remoteEndPointDescription;

        /// <summary>
        /// Initializes a new Transport.
        /// </summary>
        /// <param name="source">The listener when this transport is created from an incoming connexion.</param>
        /// <param name="remoteEndPointDescription">
        /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
        /// </param>
        /// <param name="multipleCommunicationStreams">True for Quic. This will enable a SendAndWaitAsync method (request/response streams).</param>
        protected Transport( TransportListener? source, string? remoteEndPointDescription, bool multipleCommunicationStreams = false )
        {
            _remoteEndPointDescription = remoteEndPointDescription ?? "<No EndPoint description>";
            _listener = source;
            _sendLock = multipleCommunicationStreams ? null : new SemaphoreSlim( initialCount: 1, maxCount: 1 );
            _reader = ReadExactlyAsync;
            _receiveFactory = new TransportMessageFactory();
        }

        /// <summary>
        /// Gets the listener if this transport has been initiated by this server side.
        /// Null if this transport is initiated by the remote party.
        /// </summary>
        public TransportListener? Listener => _listener;

        /// <summary>
        /// Gets a string that describes the remote's endpoint.
        /// </summary>
        public string RemoteEndPointDescription => _remoteEndPointDescription;

        /// <inheritdoc />
        public Task<TransportMessage> ReadNextAsync( int maxMessageLength = -1, CancellationToken cancellation = default )
        {
            return _receiveFactory.ReadAsync( _reader, maxMessageLength, cancellation );

            //try
            //{
            //    onKeepAlive:
            //    var m = await _receiveFactory.ReadAsync( _reader, maxMessageLength, cancellation );
            //    _lastReceived = DateTime.UtcNow;
            //    if( m == TransportMessage.Empty )
            //    {
            //        // An empty message (a single 0 byte) is not a real TransportMessage, it is the keep alive:
            //        // the other side worries about us because we did not send it any message for some time.
            //        // Let's reassure it if we are not currently sending it something.
            //        if( !_sendLock.IsEntered )
            //        {
            //            _connectionManager.OnKeepAliveReceived( this );
            //        }
            //        goto onKeepAlive;
            //    }
            //    if( m == TransportMessage.Invalid )
            //    {
            //        _connectionManager.OnInvalidReadMessage( this, ex );
            //    }
            //}
            //catch( Exception ex )
            //{
            //    _connectionManager.OnErrorReadMessage( this, ex );
            //}
            //return m;
        }

        /// <inheritdoc />
        public ValueTask<bool> SendAsync( TransportMessage message, CancellationToken cancellation = default )
        {
            Throw.CheckArgument( message != null && message.IsValid );
            return message.PrefixedMessage.IsSingleSegment
                    ? SendSingleBufferAsync( message.PrefixedMessage.First, cancellation )
                    : SendAsync( message.PrefixedMessage, cancellation );
        }

        /// <summary>
        /// Must handle the full <paramref name="buffer"/>.
        /// Calls to this methods are serialized.
        /// </summary>
        /// <param name="buffer">The buffer to send.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected abstract ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default );

        /// <summary>
        /// Sends a <see cref="ReadOnlySequence{T}"/> of bytes.
        /// This throws any error thrown by the underlying transport.
        /// This always returns true except if the operation was canceled and the <paramref name="cancellation"/> token has been signaled.
        /// <para>
        /// Default implementation simply calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> of each sequence in
        /// a <see cref="EnterSendAsync(IActivityMonitor)"/>/<see cref="LeaveSend(IActivityMonitor)"/> region).
        /// </para>
        /// <para>
        /// If the underlying transport has a support for multiple buffer sending (like <see cref="System.Net.Sockets.Socket.Send(IList{ArraySegment{byte}})"/>)
        /// this should be overridden to benefits from the performance improvement.
        /// </para>
        /// </summary>
        /// <param name="buffer">The multiple buffers to send.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>False if the <paramref name="cancellation"/> has been signaled, true otherwise.</returns>
        protected virtual async ValueTask<bool> SendAsync( ReadOnlySequence<byte> buffer, CancellationToken cancellation )
        {
            await EnterSendAsync( cancellation );
            try
            {
                foreach( var part in buffer )
                {
                    await SendAsync( part, cancellation ).ConfigureAwait( false );
                }
                return true;
            }
            catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
            {
                return false;
            }
            finally
            {
                LeaveSend();
            }
        }

        /// <summary>
        /// Must read the incoming available data and return the number of bytes read.
        /// If the underlying transport natively supports exact buffer reading, <see cref="ReadExactlyAsync(Memory{byte}, CancellationToken)"/> should be overridden.
        /// In such case this ReceiveAsync method doesn't need to implemented as it will never be called.
        /// </summary>
        /// <param name="buffer">The buffer to fill with the read data.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>The number of bytes actually read.</returns>
        protected abstract ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellation );

        /// <summary>
        /// Must read exactly the number of bytes of the <paramref name="buffer"/>.
        /// This default implementation loops on <see cref="ReceiveAsync(Memory{byte}, CancellationToken)"/> until the buffer
        /// is filled and throws an <see cref="InvalidDataException"/> if ReceiveAsync returns 0 or a negative value.
        /// <para>
        /// If the underlying transport has an efficient support of exact buffer reading this should be overridden and <see cref="ReceiveAsync(Memory{byte}, CancellationToken)"/>
        /// will never be called: this prefixed length transport only use exact buffer reading.
        /// </para>
        /// </summary>
        /// <param name="buffer">The buffer to fill.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns></returns>
        protected virtual async ValueTask ReadExactlyAsync( Memory<byte> buffer, CancellationToken cancellation )
        {
            Memory<byte> readBuffer = buffer;
            for(; ; )
            {
                int len = await ReceiveAsync( readBuffer, cancellation ).ConfigureAwait( false );
                if( len <= 0 ) Throw.InvalidDataException( $"End of stream reached on '{ToString()}'." );
                if( len == readBuffer.Length ) return;
                readBuffer = readBuffer.Slice( len );
            }
        }

        async ValueTask<bool> SendSingleBufferAsync( ReadOnlyMemory<byte> single, CancellationToken cancellation )
        {
            await EnterSendAsync( cancellation ).ConfigureAwait( false );
            try
            {
                await SendAsync( single, cancellation );
                return true;
            }
            catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
            {
                return false;
            }
            finally
            {
                LeaveSend();
            }
        }

        /// <summary>
        /// Must be called before sending. Once done <see cref="LeaveSend()"/> must be called, typically from a finally block.
        /// </summary>
        /// <param name="cancellation">The cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected Task EnterSendAsync( CancellationToken cancellation ) => _sendLock?.WaitAsync( Timeout.Infinite, cancellation ) ?? Task.CompletedTask;

        /// <summary>
        /// Leaves the lock acquired by <see cref="EnterSendAsync(CancellationToken)"/>.
        /// </summary>
        protected void LeaveSend() => _sendLock?.Release();

        internal void DisposeMessageReceiveFactory() => _receiveFactory.Dispose();

    }
}
