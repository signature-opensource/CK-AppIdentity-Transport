using CK.AppIdentity.TransportLayer.Message;
using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// This is a stable adapter between successive <see cref="Transport"/> instances and a a <see cref="TransportFeature"/>.
    /// This hosts the outgoing message channel for all protocols supported by the feature.
    /// </summary>
    sealed partial class TransportController
    {
        static readonly UnboundedChannelOptions _unboundOptions = new() { SingleReader = true };

        readonly TransportManager _transportManager;
        readonly TransportFeature _feature;
        readonly Channel<IMessage?> _senderChannel;
        readonly Channel<IMessage> _highPriorityChannel;
        Transport _transport;
        Task<IActivityMonitor>? _receiveTask;
        Task? _sendTask;

        internal TransportController( TransportManager transportManager, TransportFeature feature, Transport transport )
        {
            _transportManager = transportManager;
            _feature = feature;
            _highPriorityChannel = Channel.CreateUnbounded<IMessage>( _unboundOptions );
            // This channel should be bounded.
            _senderChannel = Channel.CreateUnbounded<IMessage?>( _unboundOptions );
            _transport = transport;
            _transport.SetController( this );
        }

        internal void Rebind( IActivityMonitor monitor, Transport transport )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            Debug.Assert( _transport.IsCondemned );
            _transport = transport;
            _transport.SetController( this );
        }

        /// <summary>
        /// Gets the current transport. It may be condemned.
        /// </summary>
        public Transport CurrentTransport => _transport;

        /// <summary>
        /// Gets the feature that manages this end point.
        /// </summary>
        public TransportFeature Feature => _feature;

        public bool TryEnqueue( IMessage message ) => _senderChannel.Writer.TryWrite( message );

        public bool TryEnqueueHighPriority( IMessage message )
        {
            if( _highPriorityChannel.Writer.TryWrite( message ) )
            {
                _senderChannel.Writer.TryWrite( null );
                return true;
            }
            return false;
        }

        /// <summary>
        /// Waits for a space to enqueue a message.
        /// </summary>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to cancel the wait operation.</param>
        /// <returns>
        /// True when a new message can be enqueued, false if the channel is closed (the remote is destroyed).
        /// </returns>
        public ValueTask<bool> WaitToEnqueueAsync( CancellationToken cancellationToken = default ) => _senderChannel.Writer.WaitToWriteAsync( cancellationToken );

        public async ValueTask<bool> TryEnqueueAsync( IMessage message, CancellationToken cancellationToken = default )
        {
            try
            {
                await _senderChannel.Writer.WriteAsync( message, cancellationToken ).ConfigureAwait( false );
                return true;
            }
            catch( OperationCanceledException ) when( cancellationToken.IsCancellationRequested )
            {
                return false;
            }
            catch( ChannelClosedException )
            {
                return false;
            }
        }

        internal void OnTransportCondemned()
        {
            // Null marker to end the send loop even if there is no message.
            _senderChannel.Writer.TryWrite( null );
        }

        internal ValueTask ActivateAsync( IActivityMonitor monitor, MessageProtocolMap protocols, PeerProtocolHandler[] handlers )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            // First starts the transport receive loop: this sets the protocol map and handlers on the transport.
            // We allow here the current receiving task to not be completed: the previous Transport can continue to receive
            // a message (in such case, we create a new monitor for the new transport).
            IActivityMonitor? receiveMonitor = null;
            if( _receiveTask != null )
            {
                Debug.Assert( _receiveTask.IsCompleted == _receiveTask.IsCompletedSuccessfully, "The receive task can only be completed successfully or pending." );
                if( _receiveTask.IsCompleted )
                {
                    receiveMonitor = _receiveTask.Result;
                }
                else
                {
                    monitor.Warn( $"Current receive task for '{_feature.Party.FullName}' is pending. A new monitor is instantiated." );
                }
            }
            // The receive loop is tied to the transport, it will end when the transport is condemned.
            _receiveTask = _transport.StartReceiveAsync( receiveMonitor, _transportManager, protocols, handlers );
            // Then start the send loop. The send loop will also end when the transport is condemned but it can be
            // stopped at any time (eviction uses this).
            if( _sendTask != null && !_sendTask.IsCompleted )
            {
                // This is rather improbable.
                return WaitToStartSendAsync( monitor );
            }
            _sendTask = Task.Run( () => RunSendAsync( _transportManager, this, _transport, _senderChannel.Reader, _highPriorityChannel.Reader ) );
            return default;
        }

        async ValueTask WaitToStartSendAsync( IActivityMonitor monitor )
        {
            Debug.Assert( _sendTask != null );
            monitor.Warn( $"Current send task for '{_feature.Party.FullName}' is pending. Waiting for its completion." );
            await _sendTask.ConfigureAwait( false );
            _sendTask = Task.Run( () => RunSendAsync( _transportManager, this, _transport, _senderChannel.Reader, _highPriorityChannel.Reader ) );
        }

        internal async ValueTask CloseAsync( IActivityMonitor monitor, string reason )
        {
            Debug.Assert( _transportManager.IsInLoop( monitor ) );
            CurrentTransport.SetSoftCondemned( new ByeByeMessage( reason.Length == 0 ? "Disposed" : reason, TimeSpan.FromSeconds( 5 ) ) );
            _highPriorityChannel.Writer.Complete();
            _senderChannel.Writer.Complete();
            // We must wait for the send task to end otherwise we'll have 2 readers activities on "single reader" channels.
            var t = _sendTask;
            if( t != null ) await t.ConfigureAwait( false );
            ClearPendingOutgoingMessages( monitor );
            _transportManager.KillTransport( CurrentTransport );
        }

        static async Task RunSendAsync( TransportManager transportManager,
                                        TransportController transportController,
                                        Transport transport,
                                        ChannelReader<IMessage?> reader,
                                        ChannelReader<IMessage> highPriorityReader )
        {
            try
            {
                Debug.Assert( transportController._transport == transport && transport.Controller == transportController );
                var handlers = transport.Handlers;
                Debug.Assert( handlers != null );
                transportManager.Logger.Trace( $"Starting sending loop for '{transport.RemoteEndPointDescription}'." );
                while( await reader.WaitToReadAsync().ConfigureAwait( false ) )
                {
                // Handle all response messages (use label/goto for code inlining: break is for the top send loop).
                responseHandling:
                    if( transport.IsCondemned )
                    {
                        break;
                    }
                    IMessage? message;
                    if( highPriorityReader.TryPeek( out message ) )
                    {
                        if( !await SendMessageAsync( transportManager, transport, message, handlers ).ConfigureAwait( false ) )
                        {
                            // Breaks the send loop. The unsent message is let in the queue.
                            break;
                        }
                        highPriorityReader.TryRead( out message );
                        goto responseHandling;
                    }
                    // Handle regular message.
                    if( reader.TryPeek( out var m ) )
                    {
                        if( m is null )
                        {
                            // Null marker is here to react to a condemned transport or StopSending.
                            // or signals a high priority message.
                            reader.TryRead( out _ );
                        }
                        else
                        {
                            if( !await SendMessageAsync( transportManager, transport, m, handlers ).ConfigureAwait( false ) )
                            {
                                // Breaks the send loop. The unsent message is let in the queue.
                                break;
                            }
                            reader.TryRead( out _ );
                        }
                    }
                }
                // Sends the bye-bye message if any.
                var byeBye = transport.ByeByeMessage;
                if( byeBye != null )
                {
                    await ZeroProtocol.SendCreateByeByeMessageAsync( transport, byeBye );
                }
                transportManager.Logger.Trace( $"Stopped sending loop for '{transport.RemoteEndPointDescription}'." );
            }
            catch( Exception ex )
            {
                Debug.Assert( ex is not ChannelClosedException, "The way we use it avoids to rely on the ChannelClosedException." );
                transportManager.Logger.Error( $"While sending message for '{transportController.Feature.Party.FullName}' to '{transport.RemoteEndPointDescription}'.", ex );
                transportManager.KillTransport( transport );
            }
        }

        static async ValueTask<bool> SendMessageAsync( TransportManager transportManager,
                                                       Transport transport,
                                                       IMessage m,
                                                       IReadOnlyList<PeerProtocolHandler> handlers )
        {
            if( m.Protocol.IsZeroProtocol )
            {
                // Even if the send is canceled in "0 Protocol", always consume the message:
                // the "0 Protocol" has no interest to interact with different transports.
                await transport.SendAsync( m ).ConfigureAwait( false );
            }
            else
            {
                int protocolIndex = transport.NegotiatedProtocols.GetProtocolIndexByName( m.Protocol.Name );
                if( protocolIndex == -1 )
                {
                    transportManager.Logger.Error( $"Got a '{m.Protocol}' message to send for transport '{transport}' but negotiated protocols are: {transport.NegotiatedProtocols}. Message is dropped." );
                }
                else
                {
                    m.SetProtocolNumber( protocolIndex + 1 );
                    PeerProtocolHandler currentHandler = handlers[protocolIndex];
                    if( currentHandler.OnSendMessage( transportManager.Logger, m, out var replacement ) )
                    {
                        var toSend = replacement ?? m;
                        if( toSend.Protocol != currentHandler.Protocol )
                        {
                            transportManager.Logger.Warn( $"{currentHandler.GetType():C}.OnSendMessage has not converted a message from '{toSend.Protocol}' to '{currentHandler.Protocol}'). Message is dropped." );
                        }
                        else
                        {
                            // If the send is canceled, ends this loop without consuming the message.
                            if( !await transport.SendAsync( toSend ).ConfigureAwait( false ) )
                            {
                                replacement?.Dispose();
                                return false;
                            }
                        }
                    }
                    replacement?.Dispose();
                }
            }
            m.Dispose();
            return true;
        }

        internal void ClearPendingOutgoingMessages( IActivityMonitor monitor, Action<IMessage>? action = null )
        {
            int count = FlushAndClose( action, _highPriorityChannel.Reader! );
            count += FlushAndClose( action, _senderChannel.Reader );
            monitor.Trace( $"Cleanup {count} unsent messages for '{_transport.RemoteEndPointDescription}'." );

            static int FlushAndClose( Action<IMessage>? action, ChannelReader<IMessage?> r )
            {
                int count = 0;
                while( r.TryRead( out var m ) )
                {
                    if( m == null ) continue;
                    ++count;
                    action?.Invoke( m );
                    m.Dispose();
                }

                return count;
            }
        }

        internal bool Receive0Message( IActivityMonitor receiveMonitor, TransportMessageImpl m )
        {
            Debug.Assert( m.Protocol == MessageProtocol.ZeroProtocol );
            if( m == TransportMessage.Empty )
            {
                // An empty message (a single 0 byte) is not a real TransportMessage, it is the keep alive:
                // the other side worries about us because we did not send it any message for some time.
                // Let's reassure it.
                receiveMonitor.Trace( $"Received KeepAlive request." );
                if( !TryEnqueue( TransportMessage.EmptyAck ) )
                {
                    receiveMonitor.Warn( $"Received a KeepAlive from '{_transport.RemoteEndPointDescription}' but our outgoing queue is full. This is weird!" );
                }
                return true;
            }
            try
            {
                switch( m.Payload.FirstSpan[0] )
                {
                    case ZeroProtocol.DRunByeBye:
                        {
                            var message = ZeroProtocol.ReadByeByeMessage( m );
                            receiveMonitor.Trace( $"Received bye-bye message: {message}" );
                            _transportManager.KillTransport( _transport, message.ShutUp );
                            return false;
                        }
                    default:
                        receiveMonitor.Warn( $"Received unknown '0 Protocol' message (Discriminator: '{m.Payload.FirstSpan[0]}', Length: {m.Payload.Length}). Ignoring it." );
                        break;
                }
                return true;
            }
            finally
            {
                m.Dispose();
            }
        }

    }
}
