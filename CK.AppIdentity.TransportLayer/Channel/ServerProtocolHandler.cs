using CK.Core;
using System.Buffers;
using System.Diagnostics;
using System.Net;

namespace CK.AppIdentity.TransportLayer
{
    public abstract class PeerProtocolHandler : IProtocolHandler
    {
        ValueTask IProtocolHandler.OnDisconnectedAsync( IActivityMonitor monitor, MessageEndPoint endPoint, Transport? potentialRecycling )
        {
            throw new NotImplementedException();
        }

        ValueTask IProtocolHandler.ReceiveAsync( MessageEndPoint endPoint, TransportMessage message )
        {
            throw new NotImplementedException();
        }

        bool IProtocolHandler.TryEnqueueUnsentMessages( TransportMessage m )
        {
            throw new NotImplementedException();
        }
    }


    /// <summary>
    /// Base class for server message handler: <see cref="TransportLayerFeature.ListeningMode"/> is
    /// <see cref="ListeningMode.RoundRobin"/> or <see cref="ListeningMode.Parallel"/>.
    /// </summary>
    public abstract class ServerProtocolHandler : IProtocolHandler
    {
        readonly TransportLayerFeature _feature;
        readonly MessageProtocol _protocol;
        readonly OutgoingMessageFactory _messageFactory;
        MessageEndPoint? _currentRoundRobin;

        /// <summary>
        /// Opaque structure for <see cref="ServerProtocolHandler"/> instantiation.
        /// Only the <see cref="Protocol"/> to support is exposed.
        /// </summary>
        public ref struct CreateParameters
        {
            internal readonly TransportLayerFeature _feature;
            readonly MessageProtocol _protocol;
            internal readonly int _protocolNumber;

            internal CreateParameters( TransportLayerFeature feature, MessageProtocol protocol, int protocolNumber )
            {
                _feature = feature;
                _protocol = protocol;
                _protocolNumber = protocolNumber;
            }

            /// <summary>
            /// Gets the message protocol that must be handled.
            /// </summary>
            public MessageProtocol Protocol => _protocol;
        }

        /// <summary>
        /// Initializes a new <see cref="ServerProtocolHandler"/> that handles <see cref="CreateParameters.Protocol"/>.
        /// </summary>
        /// <param name="parameters"></param>
        protected ServerProtocolHandler( ref CreateParameters parameters )
        {
            Throw.CheckState( parameters._feature.ListeningMode != ListeningMode.Default );
            _feature = parameters._feature;
            _protocol = parameters.Protocol;
            _messageFactory = new OutgoingMessageFactory( parameters._protocolNumber, parameters.Protocol );
        }

        /// <summary>
        /// Gets the protocol handled by this message handler.
        /// </summary>
        public MessageProtocol Protocol => _protocol;

        /// <summary>
        /// Creates a <see cref="TransportMessage"/> for this <see cref="Protocol"/> by writing its content.
        /// The <paramref name="writer"/> must write at least one byte: no protocol (other than the "0 Protocol")
        /// is allowed to send empty messages.
        /// </summary>
        /// <param name="writer">The writer function. Must write at least one byte otherwise an <see cref="InvalidOperationException"/> is thrown.</param>
        /// <param name="minSequenceBufferSize">Optional setting of the <see cref="MutableSequence{T}.MinimumBufferSize"/>.</param>
        /// <returns>A transport message.</returns>
        public TransportMessage Create( Action<IBufferWriter<byte>> writer, int minSequenceBufferSize = MutableSequence<byte>.DefaultMinimumBufferSize )
        {
            return _messageFactory.Create( writer, minSequenceBufferSize );
        }

        bool IProtocolHandler.TryEnqueueUnsentMessages( TransportMessage m ) => TryEnqueue( m );

        /// <summary>
        /// Attempts to send the message to the transport queues.
        /// Be careful: when this returns false, the message should be disposed. 
        /// </summary>
        /// <param name="message">The message to enqueue.</param>
        /// <returns>true if the message has been enqueued.</returns>
        public bool TryEnqueue( TransportMessage message )
        {
            if( _feature.ListeningMode == ListeningMode.RoundRobin )
            {
                _currentRoundRobin = _feature.LiveEndPoints.GetNext( _currentRoundRobin );
                return _currentRoundRobin != null && _currentRoundRobin.TryEnqueue( message );
            }
            else
            {
                // Parallel mode: we enqueue the message in all the alive endpoints.
                // We boost the message's reference count for each successful en-queuing
                // except the first one.
                bool success = false;
                foreach( var e in _feature.LiveEndPoints )
                {
                    if( e.TryEnqueue( message ) )
                    {
                        if( success ) message.Retain();
                        else success = true;
                    }
                }
                return success;
            }
        }

        /// <summary>
        /// Called for each received messages in this <see cref="Protocol"/>.
        /// </summary>
        /// <param name="endPoint">The receiving endpoint.</param>
        /// <param name="message">The message.</param>
        /// <returns>The awaitable.</returns>
        public abstract ValueTask ReceiveAsync( MessageEndPoint endPoint, TransportMessage message );

        ValueTask IProtocolHandler.OnDisconnectedAsync( IActivityMonitor monitor, MessageEndPoint endPoint, Transport? potentialRecycling )
        {
            if( _feature.Party.IsDestroyed )
            {
                endPoint.ClearPendingOutgoingMessages( monitor );
                return default;
            }
            return OnDisconnectedAsync( monitor, endPoint );
        }

        /// <summary>
        /// Called when a <see cref="MessageEndPoint"/> is dead.
        /// </summary>
        /// <param name="endPoint">The dead end point.</param>
        /// <returns>The awaitable.</returns>
        protected abstract ValueTask OnDisconnectedAsync( IActivityMonitor monitor, MessageEndPoint endPoint );
    }
}
