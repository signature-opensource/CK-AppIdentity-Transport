using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    public abstract class PeerProtocolHandler
    {
        readonly OutgoingMessageQueue _queue;
        readonly OutgoingMessageFactory _messageFactory;

        /// <summary>
        /// Encapsulates create parameters of <see cref="PeerProtocolHandler"/>.
        /// </summary>
        public readonly ref struct CreateParameters
        {
            internal readonly OutgoingMessageQueue _queue;
            internal readonly OutgoingMessageFactory _messageFactory;

            internal CreateParameters( OutgoingMessageQueue queue, OutgoingMessageFactory messageFactory )
            {
                _queue = queue;
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
            _queue = createParameters._queue;
            _messageFactory = createParameters._messageFactory;
        }

        /// <summary>
        /// Gets the handled protocol.
        /// </summary>
        public MessageProtocol Protocol => _messageFactory.Protocol;

        /// <summary>
        /// Gets the message factory to use.
        /// </summary>
        public OutgoingMessageFactory MessageFactory => _messageFactory;

        /// <summary>
        /// Gets the current remote end point description.
        /// This doesn't identify a remote (different remotes can be exposed by the same external address on a network).
        /// </summary>
        public string RemoteEndPointDescription => _queue.CurrentTransport.RemoteEndPointDescription;

        /// <summary>
        /// Attempts to transfer the message to the transport queue.
        /// <para>
        /// When false is returned, the <paramref name="message"/> should be disposed.
        /// </para>
        /// </summary>
        /// <param name="message">The message to enqueue.</param>
        /// <returns>true if the message has been enqueued.</returns>
        public bool TryEnqueue( TransportMessage message ) => _queue.TryEnqueue( message );

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
        public ValueTask<bool> TryEnqueueAsync( TransportMessage message, CancellationToken cancellationToken = default ) => _queue.TryEnqueueAsync( message, cancellationToken );

        /// <summary>
        /// Called for each message received.
        /// </summary>
        /// <param name="message">The message that must be disposed once done with it.</param>
        /// <returns>The awaitable.</returns>
        internal protected abstract ValueTask ReceiveAsync( TransportMessage message );

    }
}
