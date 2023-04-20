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
    /// <para>
    /// It is instantiated by a <see cref="TransportListener"/> or by <see cref="TransportTypeService.TryConnectAsync(IActivityLogger, TransportTypeAddress, CancellationToken)"/>.
    /// </para>
    /// </summary>
    public abstract partial class Transport
    {
        readonly object? _listenerOrTargetAddress;
        // Captures once for all the delegate on the ReadExactlyAsync method.
        readonly Func<Memory<byte>, CancellationToken, ValueTask> _reader;
        readonly string _remoteEndPointDescription;
        readonly IncomingMessageFactory _receiveFactory;
        // Set by StartReceive: the protocol handlers have been resolved from the
        // negotiated ones.
        PeerProtocolHandler[]? _handlers;
        // Lifetime of this transport is provided by the TransportTypeService.TryConnectToAsync
        // as soon as the Transport has been created.
        [AllowNull]
        CancellationTokenSource _cts;
        // Settable at any time: this is a soft condemned that doesn't signal the
        // LifeTime token.
        ByeByeMessage? _byeByeMessage;
        // Set when this transport has been accepted.
        TransportController? _controller;

        /// <summary>
        /// Initializes a new Transport from a <see cref="TransportListener"/>.
        /// </summary>
        /// <param name="listener">The listener that created this transport from an incoming connexion.</param>
        /// <param name="remoteEndPointDescription">
        /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
        /// </param>
        protected Transport( TransportListener listener, string? remoteEndPointDescription )
            : this( (object)listener, remoteEndPointDescription )
        {
            Throw.CheckNotNullArgument( listener );
        }

        /// <summary>
        /// Initializes a new Transport by an outgoing connection to <paramref name="targetAddress"/>.
        /// </summary>
        /// <param name="targetAddress">The target address.</param>
        /// <param name="remoteEndPointDescription">
        /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
        /// </param>
        protected Transport( TransportTypeAddress targetAddress, string? remoteEndPointDescription )
            : this( (object)targetAddress, remoteEndPointDescription )
        {
            Throw.CheckNotNullArgument( targetAddress );
        }

        Transport( object source, string? remoteEndPointDescription )
        {
            _remoteEndPointDescription = remoteEndPointDescription ?? "<No EndPoint description>";
            _listenerOrTargetAddress = source;
            _reader = ReadExactlyAsync;
            // Starts with the "0 Protocol" support only.
            // Negotiated protocols are set by StartReceiveAsync.
            _receiveFactory = new IncomingMessageFactory();
            _cts = new CancellationTokenSource();
        }

        internal void SetCancellationSource( CancellationTokenSource cancellation )
        {
            _cts = cancellation;
        }

        internal void SetController( TransportController controller )
        {
            Debug.Assert( _controller == null && controller != null );
            _controller = controller;
        }

        internal TransportController? Controller => _controller;

        /// <summary>
        /// Gets the protocols that have been negotiated.
        /// </summary>
        public MessageProtocolMap NegotiatedProtocols => _receiveFactory.AllowedProtocols;

        /// <summary>
        /// Gets the listener if this transport has been initiated by this server side.
        /// Null if this transport is initiated by an outgoing connection to <see cref="TargetAddress"/>.
        /// </summary>
        public TransportListener? Listener => _listenerOrTargetAddress as TransportListener;

        /// <summary>
        /// Gets the target address if this transport has been initiated by an outgoing connection.
        /// </summary>
        public TransportTypeAddress? TargetAddress => _listenerOrTargetAddress as TransportTypeAddress;

        /// <summary>
        /// Gets a string that describes the remote's endpoint.
        /// </summary>
        public string RemoteEndPointDescription => _remoteEndPointDescription;

        /// <summary>
        /// Gets whether this transport is condemned, either the soft way with a 
        /// </summary>
        public bool IsCondemned => _byeByeMessage != null || _cts.IsCancellationRequested;

        /// <summary>
        /// Gets the bye-bye message if it has set.
        /// </summary>
        public ByeByeMessage? ByeByeMessage => _byeByeMessage;

        /// <summary>
        /// Gets the alive token for this transport.
        /// </summary>
        public CancellationToken Lifetime => _cts.Token;

        /// <summary>
        /// Gets the last received time.
        /// </summary>
        public DateTime LastReceived => _receiveFactory.LastReceived;

        internal void SetHardCondemned()
        {
            if( !_cts.IsCancellationRequested )
            {
                _cts.Cancel();
                // Signals the send loop with a null message: this ensures that even when no
                // message are waiting, the send loop ends without relying on cancellation exception.
                _controller?.OnTransportCondemned();
            }
        }

        internal void SetSoftCondemned( ByeByeMessage m )
        {
            Debug.Assert( m != null );
            var done = IsCondemned;
            _byeByeMessage = m;
            if( !done ) _controller?.OnTransportCondemned();
        }

        /// <summary>
        /// Used during the initial negotiation.
        /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
        /// <see cref="IsCondemned"/> has been set, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// </summary>
        /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
        /// <returns>
        /// A message that may be one of the special messages <see cref="TransportMessage.Invalid"/>, <see cref="TransportMessage.Canceled"/>,
        /// <see cref="TransportMessage.Empty"/> or <see cref="TransportMessage.EmptyAck"/>.
        /// </returns>
        internal Task<TransportMessage> ReadNextAsync( int maxMessageLength = int.MaxValue )
        {
            Debug.Assert( maxMessageLength > 0 );
            Debug.Assert( _controller == null, "Not started yet." );
            return _receiveFactory.DoReadAsync( _reader, maxMessageLength, _cts.Token );
        }

        /// <summary>
        /// <see cref="TransportMessage.IsValid"/> must be true.
        /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/>
        /// if <see cref="IsCondemned"/> has been set, in such case <see cref="TransportMessage.Canceled"/> is returned.
        /// </summary>
        /// <param name="message">The valid message to send.</param>
        /// <returns>True if the message has been sent, false if <see cref="IsCondemned"/> has been signaled.</returns>
        internal ValueTask<bool> SendAsync( TransportMessage message )
        {
            Throw.CheckArgument( message != null && message.IsValid );
            if( _cts.IsCancellationRequested ) return ValueTask.FromResult( false );
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
        /// Default implementation simply calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> on each sequence.
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

        internal ValueTask DestroyAsync( IActivityMonitor monitor )
        {
            _receiveFactory.Dispose();
            return DisposeAsync( monitor );
        }

        /// <summary>
        /// Must close any communication handle.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>The awaitable.</returns>
        protected abstract ValueTask DisposeAsync( IActivityMonitor monitor );

        /// <summary>
        /// Overridden to return the type name and the <see cref="RemoteEndPointDescription"/>.
        /// </summary>
        /// <returns>A readable string.</returns>
        public override string ToString() => $"{GetType().Name} - {_remoteEndPointDescription}";

    }
}
