using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.SymbolStore;
using System.Reflection.Emit;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// A Transport is able to send and receive <see cref="TransportMessage"/>.
    /// Concrete implementations can be <see cref="IAsyncDisposable"/> or <see cref="IDisposable"/>:
    /// the connection manager will prefer <see cref="IAsyncDisposable"/> and will call the latter otherwise.
    /// </summary>
    public abstract partial class Transport
    {
        readonly TransportListener? _listener;
        // Captures once for all the delegate on the ReadExactlyAsync method.
        readonly Func<Memory<byte>, CancellationToken, ValueTask> _reader;
        readonly string _remoteEndPointDescription;
        readonly IncomingMessageFactory _receiveFactory;
        // Set by StartReceive: the protocol handlers have been resolved from the
        // negotiated ones.
        IProtocolHandler[]? _handlers;
        // Lifetime of this transport is provided by the TransportTypeService.TryConnectToAsync
        // as soon as the Transport has been created.
        [AllowNull]
        CancellationTokenSource _cts;
        MessageEndPoint? _endPoint;

        /// <summary>
        /// Initializes a new Transport.
        /// </summary>
        /// <param name="source">The listener when this transport is created from an incoming connexion.</param>
        /// <param name="remoteEndPointDescription">
        /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
        /// </param>
        protected Transport( TransportListener? source, string? remoteEndPointDescription )
        {
            _remoteEndPointDescription = remoteEndPointDescription ?? "<No EndPoint description>";
            _listener = source;
            _reader = ReadExactlyAsync;
            // Starts with the "0 Protocol" support only.
            _receiveFactory = new IncomingMessageFactory();
            _cts = new CancellationTokenSource();
        }

        internal void SetCancellationSource( CancellationTokenSource cancellation )
        {
            _cts = cancellation;
        }

        internal void SetMessageEndPoint( MessageEndPoint messageEndPoint )
        {
            Debug.Assert( _endPoint == null && messageEndPoint != null );
            _endPoint = messageEndPoint;
        }

        internal MessageEndPoint? EndPoint => _endPoint;

        /// <summary>
        /// Gets the protocols that have been negotiated.
        /// </summary>
        public MessageProtocolMap NegotiatedProtocols => _receiveFactory.AllowedProtocols;

        /// <summary>
        /// Gets the listener if this transport has been initiated by this server side.
        /// Null if this transport is initiated by the remote party.
        /// </summary>
        public TransportListener? Listener => _listener;

        /// <summary>
        /// Gets a string that describes the remote's endpoint.
        /// </summary>
        public string RemoteEndPointDescription => _remoteEndPointDescription;

        /// <summary>
        /// Gets whether this transport is condemned.
        /// </summary>
        public bool IsCondemned => _cts.IsCancellationRequested;

        /// <summary>
        /// Gets the alive token for this transport.
        /// </summary>
        public CancellationToken Lifetime => _cts.Token;

        internal void SetCondemned()
        {
            if( !_cts.IsCancellationRequested )
            {
                _cts.Cancel();
                _endPoint?.OnTransportSetCondemned();
            }
        }

        /// <summary>
        /// Used during the initial negotiation.
        /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
        /// <see cref="IsCondemned"/> has been set, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// </summary>
        /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
        /// <returns>
        /// A message that may be one of the <see cref="TransportMessage.Invalid"/>, <see cref="TransportMessage.Canceled"/> or <see cref="TransportMessage.Empty"/>
        /// special messages.
        /// </returns>
        internal Task<TransportMessage> ReadNextAsync( int maxMessageLength = int.MaxValue )
        {
            Debug.Assert( maxMessageLength > 0 );
            Debug.Assert( _endPoint == null, "Not started yet." );
            return _receiveFactory.DoReadAsync( _reader, maxMessageLength, _cts.Token );
        }

        /// <summary>
        /// Used during the initial negotiation.
        /// <see cref="TransportMessage.IsValid"/> must be true.
        /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/>
        /// if <see cref="IsCondemned"/> has been set, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// </summary>
        /// <param name="message">The valid message to send.</param>
        /// <returns>True if the message has been sent, false if <see cref="IsCondemned"/> has been signaled.</returns>
        internal ValueTask<bool> SendAsync( TransportMessage message )
        {
            Throw.CheckArgument( message != null && message.IsValid );
            Debug.Assert( _endPoint == null, "Not started yet." );
            return message.WireMessage.IsSingleSegment
                    ? SendSingleBufferAsync( message.WireMessage.First, _cts.Token )
                    : SendAsync( message.WireMessage, _cts.Token );
        }

        /// <summary>
        /// Must handle the full <paramref name="buffer"/>.
        /// Calls to this methods are serialized.
        /// </summary>
        /// <param name="buffer">The buffer to send.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The awaitable.</returns>
        protected abstract ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken );

        /// <summary>
        /// Sends a <see cref="ReadOnlySequence{T}"/> of bytes.
        /// This throws any error thrown by the underlying transport.
        /// This always returns true except if the operation was canceled and the <paramref name="cancellation"/> token has been signaled.
        /// <para>
        /// <para>
        /// Default implementation simply calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> of each sequence.
        /// </para>
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
        }

        /// <summary>
        /// Must read the incoming available data and return the number of bytes read.
        /// If the underlying transport natively supports exact buffer reading, <see cref="ReadExactlyAsync(Memory{byte}, CancellationToken)"/> should be overridden.
        /// In such case this ReceiveAsync method doesn't need to be implemented (it will never be called).
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
        /// <returns>The awaitable.</returns>
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
            try
            {
                await SendAsync( single, cancellation ).ConfigureAwait( false );
                return true;
            }
            catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
            {
                return false;
            }
        }

        internal void DisposeMessageReceiveFactory() => _receiveFactory.Dispose();

    }
}
