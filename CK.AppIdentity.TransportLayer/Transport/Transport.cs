using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;


/// <summary>
/// A Transport is able to send <see cref="IOutgoingMessage"/> and receive <see cref="IncomingMessage"/>.
/// <para>
/// It is instantiated by a <see cref="TransportListener"/> or
/// by <see cref="TransportTypeService.TryConnectAsync(IParallelLogger, TransportTypeAddress, IRemoteKeys, CancellationToken)"/>.
/// </para>
/// </summary>
public abstract partial class Transport
{
    readonly object? _listenerOrTargetAddress;
    // Captures once for all the delegate on the ReadExactlyAsync method.
    readonly Func<Memory<byte>, CancellationToken, ValueTask> _reader;
    readonly string _remoteEndPointDescription;
    readonly IncomingMessageFactory _receiveFactory;
    // StartReceiveAsync sets:
    //  - _receiveHandlers: With the protocol handlers have been resolved from the negotiated ones.
    //  - _receiveCTS: A new CancellationTokenSource created right before calling RunReceiveAsync.
    //                 The Token is provided to _receiveFactory.DoReadAsync for each read.
    PeerProtocolHandler[]? _receiveHandlers;
    CancellationTokenSource? _receiveCTS;

    // Set when this transport has been accepted.
    TransportController? _controller;

    // Ultimate lifetime. 
    // Initiator: Lifetime of this transport is provided by the TransportTypeService.TryConnectToAsync
    //            as soon as the Transport has been created.
    // Listener: Initialized in the constructor.
    [AllowNull]
    CancellationTokenSource _lifeTime;

    // Initiator: This known at the Transport creation time.
    // Listener: This is set by the IncomingConnectionBackTask if the remote party exists.
    IRemoteKeys? _remoteKeys;

    // Set by the TransportController on the TransportManager loop : this is a soft
    // condemned that doesn't signal the LifeTime token.
    GoodbyeMessage? _goodbyeMessage;

    int _disposed;

    /// <summary>
    /// Initializes a new Transport from a <see cref="TransportListener"/>.
    /// </summary>
    /// <param name="listener">The listener that created this transport from an incoming connexion.</param>
    /// <param name="remoteEndPointDescription">
    /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
    /// </param>
    /// <param name="remoteKeys">
    /// When not null, it means that the TransportListener was able to resolve the remote party
    /// among the <see cref="TransportListener.Parties"/>. This is possible for secured connections
    /// when a SSL certificates is available.
    /// </param>
    protected Transport( TransportListener listener,
                         string? remoteEndPointDescription,
                         IRemoteKeys? remoteKeys = null )
        : this( listener._transportManager.SystemClock,
                (object)listener,
                remoteEndPointDescription,
                remoteKeys )
    {
        Throw.CheckNotNullArgument( listener );
    }

    /// <summary>
    /// Initializes a new Transport by an outgoing connection to <paramref name="targetAddress"/>.
    /// We are on a known remote: the local and remote keys are known in this case.
    /// </summary>
    /// <param name="targetAddress">The target address.</param>
    /// <param name="remoteKeys">Remote key manager of this remote party.</param>
    /// <param name="remoteEndPointDescription">
    /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
    /// </param>
    protected Transport( TransportTypeAddress targetAddress,
                         IRemoteKeys remoteKeys,
                         string? remoteEndPointDescription )
        : this( remoteKeys.Party.ApplicationIdentityService.SystemClock,
                (object)targetAddress,
                remoteEndPointDescription,
                remoteKeys )
    {
        Throw.CheckArgument( remoteKeys != null );
        Throw.CheckNotNullArgument( targetAddress );
    }

    Transport( ISystemClock systemClock,
               object source,
               string? remoteEndPointDescription,
               IRemoteKeys? remoteKeys )
    {
        _remoteEndPointDescription = remoteEndPointDescription ?? "<No EndPoint description>";
        _listenerOrTargetAddress = source;
        _reader = ReadExactlyAsync;
        // Starts with the "0 Protocol" support only.
        // Negotiated protocols are set by StartReceiveAsync.
        _receiveFactory = new IncomingMessageFactory( systemClock );
        _lifeTime = new CancellationTokenSource();
        _remoteKeys = remoteKeys;
    }

    internal void SetCancellationSource( CancellationTokenSource cancellation )
    {
        _lifeTime = cancellation;
    }

    internal void SetController( TransportController controller )
    {
        Throw.DebugAssert( _controller == null && controller != null );
        _controller = controller;
    }

    internal TransportController? Controller => _controller;

    /// <summary>
    /// Gets the protocols that have been negotiated.
    /// </summary>
    public MessageProtocolMap NegotiatedProtocols => _receiveFactory.AllowedProtocols;

    /// <summary>
    /// Gets the listener if this transport is on the listening side.
    /// Null if this transport is the initiator to the non null <see cref="TargetAddress"/>.
    /// </summary>
    public TransportListener? Listener => _listenerOrTargetAddress as TransportListener;

    /// <summary>
    /// Gets the target address if this transport has initiated the connection.
    /// </summary>
    public TransportTypeAddress? TargetAddress => _listenerOrTargetAddress as TransportTypeAddress;

    /// <summary>
    /// Gets a string that describes the remote's endpoint.
    /// </summary>
    public string RemoteEndPointDescription => _remoteEndPointDescription;

    /// <summary>
    /// Gets whether this transport is condemned (or is already dead).
    /// </summary>
    public bool IsCondemned => _goodbyeMessage != null || _lifeTime.IsCancellationRequested;

    /// <summary>
    /// Gets the goodbye message if it has been set.
    /// </summary>
    public GoodbyeMessage? GoodbyeMessage => _goodbyeMessage;

    /// <summary>
    /// Gets the alive token for this transport.
    /// </summary>
    /// <remarks>
    /// This is used as the cancellation token when reading and writing messages.
    /// </remarks>
    public CancellationToken Lifetime => _lifeTime.Token;

    /// <summary>
    /// Gets the last received time.
    /// </summary>
    public DateTime LastReceived => _receiveFactory.LastReceived;

    internal IRemoteKeys? RemoteKeys => _remoteKeys;

    internal void SetKeys( IRemoteKeys remoteKeys )
    {
        Throw.DebugAssert( _remoteKeys == null );
        _remoteKeys = remoteKeys;
    }

    /// <summary>
    /// Called by TransportManager.KillTransport before pushing the transport to be disposed:
    /// this signals the <see cref="Lifetime"/> token and may let some time for the cancellation
    /// to be honored before disposing the transport.
    /// Note that we may have already been SoftCondemned.
    /// </summary>
    /// <returns>False if this transport was already killed.</returns>
    internal bool OnKilled()
    {
        // Why does CTS.Cancel() doesn't return a bool?
        // It has already a CompareExchange!
        if( Interlocked.CompareExchange( ref _disposed, 1, 0 ) == 0 )
        {
            // Signal the cancellation first.
            _lifeTime.Cancel();
            // Then sends the awaker to the send loop: it will see
            // a condemn transport end exits.
            _controller?.OnKilledTransport();
            return true;
        }
        return false;
    }

    /// <summary>
    /// This is thread safe because this can be called from
    /// the TransportManager loop and from the Receive loop when a Goodbye message
    /// from the remote has been received.
    /// </summary>
    internal bool Condemn( GoodbyeMessage m )
    {
        if( Interlocked.CompareExchange( ref _goodbyeMessage, m, null) == null )
        {
            // Stops the receive loop as soon as poosible.
            _receiveCTS?.Cancel();
            return true;
        }
        return false;
    }

    /// <summary>
    /// <see cref="OutgoingMessage.IsValid"/> must be true.
    /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/>
    /// if <see cref="IsCondemned"/> has been set, in such case false is returned.
    /// </summary>
    /// <param name="message">The valid message to send.</param>
    /// <returns>True if the message has been sent, false if <see cref="IsCondemned"/> has been signaled.</returns>
    internal async ValueTask<bool> SendAsync( uint protocolNumber, IOutgoingMessage message )
    {
        Throw.DebugAssert( message != null );
        Throw.DebugAssert( message.IsValid );

        if( _lifeTime.IsCancellationRequested ) return false;

        // The header must stay rented until the send has actually completed: the underlying
        // socket keeps referencing it across every await below. Returning it earlier puts a
        // live buffer back in the shared pool and mis-frames the stream.
        var header = ArrayPool<byte>.Shared.Rent( IOutgoingMessage.MaxWirePrefixLength );
        try
        {
            int len = IOutgoingMessage.WriteWireHeader( protocolNumber, (uint)message.Message.Length, message.IsControl, header );
            var messagePrefix = header.AsMemory( 0, len );
            return await SendAsync( messagePrefix, message.Message, _lifeTime.Token ).ConfigureAwait( false );
        }
        finally
        {
            ArrayPool<byte>.Shared.Return( header );
        }
    }

    /// <summary>
    /// Root method that calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> with
    /// the <paramref name="messagePrefix"/> and then <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/>
    /// (mono buffer again) or <see cref="SendAsync(ReadOnlySequence{byte}, CancellationToken)"/> (when the message has multiple buffer).
    /// <para>
    /// Calls to this methods are serialized.
    /// </para>
    /// </summary>
    /// <param name="message">The message body.</param>
    /// <param name="messagePrefix">The message prefix.</param>
    /// <returns>False if the <paramref name="cancellation"/> has been signaled, true otherwise.</returns>
    protected virtual async ValueTask<bool> SendAsync( ReadOnlyMemory<byte> messagePrefix, ReadOnlySequence<byte> message, CancellationToken cancellation )
    {
        try
        {
            await SendAsync( messagePrefix, _lifeTime.Token );
            if( message.IsSingleSegment )
            {
                await SendAsync( message.First, _lifeTime.Token );
            }
            else
            {
                await SendAsync( message, _lifeTime.Token );
            }
            return true;
        }
        catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
        {
            return false;
        }
    }

    /// <summary>
    /// Must handle the full <paramref name="buffer"/>.
    /// Calls to this methods are serialized.
    /// </summary>
    /// <param name="buffer">The buffer to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The awaitable.</returns>
    internal protected abstract ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken );

    /// <summary>
    /// Sends a <see cref="ReadOnlySequence{T}"/> of bytes.
    /// This throws any error thrown by the underlying transport.
    /// This always returns true except if the operation was canceled and the <paramref name="cancellation"/> token has been signaled.
    /// <para>
    /// <para>
    /// Default implementation simply calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> on each segment.
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
    /// In such case this ReceiveAsync method doesn't need to be supported (it will never be called).
    /// </summary>
    /// <param name="buffer">The buffer to fill with the read data.</param>
    /// <param name="cancellation">Cancellation token.</param>
    /// <returns>The number of bytes actually read.</returns>
    protected abstract ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellation );

    /// <summary>
    /// Must read exactly the number of bytes of the <paramref name="buffer"/>.
    /// This default implementation loops on <see cref="ReceiveAsync(Memory{byte}, CancellationToken)"/> until the buffer
    /// is filled and throws a <see cref="System.IO.InvalidDataException"/> if ReceiveAsync returns 0 or a negative value.
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

    internal ValueTask DestroyAsync( IActivityMonitor monitor )
    {
        _receiveFactory.Dispose();
        return DisposeAsync( monitor );
    }

    /// <summary>
    /// Must close any communication handle.
    /// This is guraranteed to be called once and only once.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>The awaitable.</returns>
    protected abstract ValueTask DisposeAsync( IActivityMonitor monitor );

    /// <summary>
    /// Overridden to return the type name, the <see cref="RemoteEndPointDescription"/> (and <see cref="IsCondemned"/>
    /// if it is true).
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => $"{GetType().Name} - {_remoteEndPointDescription}{(IsCondemned ? " (Condemned)" : "")}";

}
