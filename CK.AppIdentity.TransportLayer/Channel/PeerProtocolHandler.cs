using CK.Core;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

public abstract class PeerProtocolHandler
{
    readonly TransportController _controller;
    readonly OutgoingMessageFactory _messageFactory;
    internal readonly PeerProtocolHandler? _nextHandler;

    /// <summary>
    /// Encapsulates create parameters of <see cref="PeerProtocolHandler"/>.
    /// </summary>
    public readonly ref struct CreateParameters
    {
        internal readonly PeerProtocolHandler? _nextHandler;
        internal readonly TransportController _controller;
        internal readonly OutgoingMessageFactory _messageFactory;

        internal CreateParameters( PeerProtocolHandler? nextHandler, TransportController queue, OutgoingMessageFactory messageFactory )
        {
            _nextHandler = nextHandler;
            _controller = queue;
            _messageFactory = messageFactory;
        }

        /// <summary>
        /// Gets the message protocol that must be handled.
        /// </summary>
        public MessageProtocol Protocol => _messageFactory.Protocol;
    }

    /// <summary>
    /// Instantiates a new <see cref="PeerProtocolHandler"/>.
    /// </summary>
    /// <param name="createParameters">Opaque (except <see cref="CreateParameters.Protocol"/>) required parameters.</param>
    protected PeerProtocolHandler( ref CreateParameters createParameters )
    {
        _controller = createParameters._controller;
        _messageFactory = createParameters._messageFactory;
        _nextHandler = createParameters._nextHandler;
    }

    /// <summary>
    /// Gets the handled protocol.
    /// </summary>
    public MessageProtocol Protocol => _messageFactory.Protocol;

    /// <summary>
    /// Gets the message factory to use.
    /// </summary>
    protected OutgoingMessageFactory MessageFactory => _messageFactory;

    /// <summary>
    /// Gets the current remote end point description.
    /// This doesn't identify a remote (different remotes can be exposed by the same external address on a network).
    /// </summary>
    public string RemoteEndPointDescription => _controller.CurrentTransport.RemoteEndPointDescription;

    /// <summary>
    /// Attempts to transfer the message to the transport queue.
    /// <para>
    /// When false is returned, the <paramref name="message"/> should be released.
    /// </para>
    /// </summary>
    /// <param name="message">The message to enqueue.</param>
    /// <returns>true if the message has been enqueued.</returns>
    public bool TryEnqueue( IOutgoingMessage message ) => _controller.TryEnqueue( message );

    /// <summary>
    /// Attempts to transfer the message to the transport high priority queue.
    /// <para>
    /// This returns false if and only if the channel is closed (the remote is destroyed).
    /// When false is returned, the <paramref name="message"/> should be released.
    /// </para>
    /// </summary>
    /// <param name="message">The message to enqueue.</param>
    /// <returns>true if the message has been enqueued, false if the remote has been destroyed.</returns>
    public bool TryEnqueueHighPriority( IOutgoingMessage message )
    {
        return _controller.TryEnqueueHighPriority( message );
    }

    /// <summary>
    /// Asynchronously tries to enqueue a message, waiting for the message to be enqueued.
    /// <para>
    /// When false is returned, the <paramref name="message"/> should be disposed.
    /// </para>
    /// </summary>
    /// <param name="message">The message to enqueue.</param>
    /// <param name="cancellationToken">Optional <see cref="CancellationToken"/>.</param>
    /// <returns>
    /// True if the message has been be enqueued, false if the channel is closed (the remote is destroyed)
    /// or the <paramref name="cancellationToken"/> has been signaled.
    /// </returns>
    public ValueTask<bool> TryEnqueueAsync( IOutgoingMessage message, CancellationToken cancellationToken = default ) => _controller.TryEnqueueAsync( message, cancellationToken );

    /// <summary>
    /// Called for each message received.
    /// </summary>
    /// <param name="monitor">The receiving monitor.</param>
    /// <param name="message">The message that must be disposed once done with it.</param>
    /// <returns>The awaitable.</returns>
    internal protected abstract ValueTask ReceiveAsync( IActivityMonitor monitor, IncomingMessage message );

    /// <summary>
    /// Called right before a message is sent to the remote. Does nothing by default (always returns true).
    /// <para>
    /// The <paramref name="replacement"/> can be used to implement version conversion if the message's protocol differ
    /// from this <see cref="Protocol"/>.
    /// </para>
    /// <para>
    /// <b>This must be side effect free.</b> A send that fails leaves the message in the queue so that
    /// it can be retried, and this is called again on each attempt — possibly many times for one
    /// message. Anything that must happen exactly once belongs in <see cref="OnMessageSent"/>.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="message">The message that is about to be sent.</param>
    /// <param name="replacement">Optional message that will be sent instead of the queued <paramref name="message"/>.</param>
    /// <returns>True to send the message, false to skip it.</returns>
    internal protected virtual bool OnSendMessage( IParallelLogger logger, IOutgoingMessageData message, out IOutgoingMessage? replacement )
    {
        replacement = null;
        return true;
    }

    /// <summary>
    /// Called once the message has actually reached the transport. Does nothing by default.
    /// <para>
    /// This is where a side effect belongs — unlike <see cref="OnSendMessage"/> it runs exactly once
    /// per message, and only when the send succeeded.
    /// </para>
    /// <para>
    /// The message is the one that was queued, not any replacement produced by
    /// <see cref="OnSendMessage"/>, so that <see cref="IOutgoingMessageData.Source"/> is still the
    /// object the application enqueued.
    /// </para>
    /// <para>
    /// An exception thrown here is logged and swallowed: the message is already gone, so failing
    /// must not push the send loop into resending it.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="message">The message that was sent.</param>
    internal protected virtual void OnMessageSent( IParallelLogger logger, IOutgoingMessageData message )
    {
    }
}
