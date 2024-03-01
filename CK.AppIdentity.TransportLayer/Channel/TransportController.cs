using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// This is a stable adapter between successive <see cref="Transport"/> instances and a a <see cref="TransportFeature"/>.
    /// This hosts the outgoing message channels for all protocols supported by the feature.
    /// </summary>
    sealed partial class TransportController
    {
        static readonly UnboundedChannelOptions _unboundOptions = new() { SingleReader = true };

        readonly TransportManager _transportManager;
        readonly TransportFeature _feature;
        // Null is the awaker for the priority messages and closing.
        readonly Channel<IOutgoingMessage?> _senderChannel;
        readonly Channel<IOutgoingMessage> _highPriorityChannel;
        Transport _transport;
        Task<IActivityMonitor>? _receiveTask;
        // Never null: initialized with a completed task.
        Task _sendTask;

        internal TransportController( TransportManager transportManager, TransportFeature feature, Transport transport )
        {
            _transportManager = transportManager;
            _feature = feature;
            _highPriorityChannel = Channel.CreateUnbounded<IOutgoingMessage>( _unboundOptions );
            // This channel should be bounded.
            _senderChannel = Channel.CreateUnbounded<IOutgoingMessage?>( _unboundOptions );
            _sendTask = Task.CompletedTask;
            _transport = transport;
            _transport.SetController( this );
        }

        internal void Rebind( IActivityMonitor monitor, Transport transport, GoodbyeMessage.Evicted? evictionMessage )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( evictionMessage != null )
            {
                CloseCurrentTransport( monitor, evictionMessage );
            }
            else
            {
                // If we have no evictionMessage then we are an initiator and our
                // current transport is dead: the _sendTask is completed.
                Throw.DebugAssert( !_feature.IsListening && _transport.IsCondemned && _sendTask.IsCompleted );
            }
            _transport = transport;
            transport.SetController( this );
        }

        /// <summary>
        /// Gets the current transport. It may be condemned.
        /// </summary>
        public Transport CurrentTransport => _transport;

        /// <summary>
        /// Gets the feature that manages this end point.
        /// </summary>
        public TransportFeature Feature => _feature;

        public bool TryEnqueue( IOutgoingMessage message ) => _senderChannel.Writer.TryWrite( message );

        public bool TryEnqueueHighPriority( IOutgoingMessage message )
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
        /// True when a new message can be enqueued, false if the channel is closed (the remote is destroyed)
        /// or the <paramref name="cancellationToken"/> has been signaled.
        /// </returns>
        public ValueTask<bool> WaitToEnqueueAsync( CancellationToken cancellationToken = default ) => _senderChannel.Writer.WaitToWriteAsync( cancellationToken );

        public async ValueTask<bool> TryEnqueueAsync( IOutgoingMessage message, CancellationToken cancellationToken = default )
        {
            try
            {
                await _senderChannel.Writer.WriteAsync( message, cancellationToken ).ConfigureAwait( false );
                return true;
            }
            catch( OperationCanceledException ) when ( cancellationToken.IsCancellationRequested )
            {
                return false;
            }
            catch( ChannelClosedException )
            {
                return false;
            }
        }

        internal ValueTask ActivateAsync( IActivityMonitor monitor, MessageProtocolMap protocols, PeerProtocolHandler[] handlers )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            // First starts the transport receive loop: this sets the protocol map and handlers on the transport.
            // We allow here the current receiving task to not be completed: the previous Transport can continue to receive
            // a message (in such case, we create a new monitor for the new transport).
            IActivityMonitor? receiveMonitor = null;
            if( _receiveTask != null )
            {
                Throw.DebugAssert( "The receive task can only be completed successfully or pending.",
                                   _receiveTask.IsCompleted == _receiveTask.IsCompletedSuccessfully );
                if( _receiveTask.IsCompleted )
                {
#pragma warning disable VSTHRD103 // _receiveTask.IsCompleted is true.
                    receiveMonitor = _receiveTask.Result;
#pragma warning restore VSTHRD103 // Call async methods when in an async method
                }
                else
                {
                    monitor.Warn( $"Current receive task for '{_feature.Party.FullName}' is pending. A new monitor is instantiated." );
                }
            }
            // The receive loop is controlled by a receive CTS that can be signaled by the Transport.LifeTime token
            // or by a GoodbyeMessage.
            _receiveTask = _transport.StartReceiveAsync( receiveMonitor, _transportManager, protocols, handlers );
            // Then start the send loop after the completion of the previous one.
            if( !_sendTask.IsCompleted )
            {
                return WaitToStartSendAsync( monitor );
            }
            _sendTask = Task.Run( () => RunSendAsync( _transportManager, this, _transport, _senderChannel.Reader, _highPriorityChannel.Reader ) );
            return default;
        }

        async ValueTask WaitToStartSendAsync( IActivityMonitor monitor )
        {
            monitor.Warn( $"Current send task for '{_feature.Party.FullName}' is pending. Waiting for its completion." );

            _transportManager.DelayedKillTransport( _transport, int.MaxValue );
            await _sendTask.ConfigureAwait( false );
            _sendTask = Task.Run( () => RunSendAsync( _transportManager, this, _transport, _senderChannel.Reader, _highPriorityChannel.Reader ) );
        }

        internal async ValueTask CloseAsync( IActivityMonitor monitor, GoodbyeMessage reason )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            CloseCurrentTransport( monitor, reason );
            // Close the channels: this controller is dead.
            _highPriorityChannel.Writer.Complete();
            _senderChannel.Writer.Complete();
            // We must wait for the send task to end otherwise we'll have 2 readers activities on "single reader" channels
            // while clearing pending outgoing messages.
            if( !_sendTask.IsCompleted )
            {
                await _sendTask.ConfigureAwait( false );
            }
            // Drain queued outgoing messages: they must be released.
            ClearPendingOutgoingMessages( monitor );
            // Kill the transport and don't trigger any retry if this is an outgoing transport.
            // If the sendTask is completed, it's the opportunity to not wait for 1 second.
            if( _sendTask.IsCompleted ) _transportManager.KillTransport( CurrentTransport, int.MaxValue );
        }

        internal void OnKilledTransport()
        {
            _senderChannel.Writer.TryWrite( null );
        }

        void CloseCurrentTransport( IActivityMonitor monitor, GoodbyeMessage goodbye )
        {
            Throw.DebugAssert( _transportManager.IsInLoop( monitor ) );
            if( _transport.Condemn( goodbye ) )
            {
                // _transport.Condemn ensures that the cancellation token of the Receive loop is signaled.
                //
                // Awake the send loop that will
                //   - see a condemned transport,
                //   - breaks its loop
                //   - sends the GoodbyeMessage (if it's not from the remote) with the Transport.LifeTime token.
                //   - and this eventually completes the _sendTask...
                _senderChannel.Writer.TryWrite( null );
                // But if something is blocked in the message sending (that uses the transport.LifeTime token),
                // the _sendTask may block "too much" (especially because we await the _sendTask from the
                // TransportManager loop).
                // Let some time to the sendTask to end before killing the transport and don't trigger
                // any retry if this is an outgoing transport: we are rebinding (to a new transport with an eviction message
                // to send to the current transport or we are closing this controller because the TransportFeature is switched off). 
                _transportManager.DelayedKillTransport( _transport, int.MaxValue );
            }
        }

        // There is no "sendCTS" here, only the lookup to transport.IsCondemned.
        // A sendCTS would be useful if cancelling a send was "atomic" (no bytes of the message would be sent): in such
        // case we would then be able to send the goodbye message (if any) before exiting the loop (and completing the task).
        // Unfortunately, this super feature is missing!
        // So we simply use the transport.LifeTime token and if a big message is being sent and takes too long, we
        // won't be able to send the Goodbye message.
        static async Task RunSendAsync( TransportManager transportManager,
                                        TransportController transportController,
                                        Transport transport,
                                        ChannelReader<IOutgoingMessage?> reader,
                                        ChannelReader<IOutgoingMessage> highPriorityReader )
        {
            try
            {
                Throw.DebugAssert( transportController._transport ==  transport && transport.Controller == transportController );
                var handlers = transport.Handlers;
                Throw.DebugAssert( handlers != null );
                transportManager.Logger.Trace( $"Starting sending loop for '{transport.RemoteEndPointDescription}'." );
                while( await reader.WaitToReadAsync().ConfigureAwait( false ) )
                {
                    // Handle all high priority messages (use label/goto for code inlining: break is for the top send loop).
                    responseHandling:
                    if( transport.IsCondemned )
                    {
                        break;
                    }
                    if( highPriorityReader.TryPeek( out var m ) )
                    {
                        if( !await SendMessageAsync( transportManager, transport, m, handlers ).ConfigureAwait( false ) )
                        {
                            // Breaks the send loop. The unsent message is let in the queue.
                            break;
                        }
                        highPriorityReader.TryRead( out m );
                        goto responseHandling;
                    }
                    // Handle regular message.
                    if( reader.TryPeek( out m ) )
                    {
                        if( m == null )
                        {
                            // Null awaker is here to react to a condemned transport or StopSending.
                            // or signals a high priority message.
                            reader.TryRead( out m );
                        }
                        else
                        {
                            if( !await SendMessageAsync( transportManager, transport, m, handlers ).ConfigureAwait( false ) )
                            {
                                // Breaks the send loop. The unsent message is let in the queue.
                                break;
                            }
                            reader.TryRead( out m );
                        }
                    }
                }
                // Sends the bye-bye message if any.
                // ZeroProtocol always use the transport.LifeTime token.
                var byeBye = transport.GoodbyeMessage;
                if( byeBye != null && !byeBye.IsFromRemote && !transport.Lifetime.IsCancellationRequested )
                {
                    transportManager.Logger.Trace( $"Sending goodbye message '{byeBye}' and stopping sending loop for '{transport.RemoteEndPointDescription}'." );
                    await ZeroProtocol.SendGoodbyeMessageAsync( transport, byeBye );
                }
                else
                {
                    transportManager.Logger.Trace( $"Stopped sending loop for '{transport.RemoteEndPointDescription}'." );
                }
            }
            catch( Exception ex )
            {
                Throw.DebugAssert( "The way we use it avoids to rely on the ChannelClosedException.", ex is not ChannelClosedException );
                transportManager.Logger.Error( $"While sending message for '{transportController.Feature.Party.FullName}' to '{transport.RemoteEndPointDescription}'.", ex );
                // Kill this buggy transport and retry asap if this is an outgoing connection.
                transportManager.KillTransport( transport, 0 );
            }

            static async ValueTask<bool> SendMessageAsync( TransportManager transportManager,
                                                           Transport transport,
                                                           IOutgoingMessage m,
                                                           IReadOnlyList<PeerProtocolHandler> handlers )
            {
                if( m.Protocol.IsZeroProtocol )
                {
                    // Even if the send is canceled in "0 Protocol", always consume the message:
                    // the "0 Protocol" must not interact with different transports.
                    await transport.SendAsync( 0, m ).ConfigureAwait( false );
                }
                else
                {
                    int protocolNumber = transport.NegotiatedProtocols.GetProtocolIndexByName( m.Protocol.Name );
                    if( protocolNumber == -1 )
                    {
                        transportManager.Logger.Error( $"Got a '{m.Protocol}' message to send for transport '{transport}' but negotiated protocols are: {transport.NegotiatedProtocols}. Message is dropped." );
                    }
                    else
                    {
                        PeerProtocolHandler currentHandler = handlers[protocolNumber];
                        if( currentHandler.OnSendMessage( transportManager.Logger, m, out var replacement ) )
                        {
                            var toSend = replacement ?? m;
                            if( toSend.Protocol != currentHandler.Protocol )
                            {
                                transportManager.Logger.Warn( $"{currentHandler.GetType():C}.OnSendMessage has not converted a message from '{toSend.Protocol}' to '{currentHandler.Protocol}'). Message is dropped." );
                            }
                            else
                            {
                                // If the send is canceled, returns without consuming the message.
                                if( !await transport.SendAsync( (uint)protocolNumber + 1, toSend ).ConfigureAwait( false ) )
                                {
                                    replacement?.Release();
                                    return false;
                                }
                            }
                        }
                        replacement?.Release();
                    }
                }
                m.Release();
                return true;
            }

        }

        internal void ClearPendingOutgoingMessages( IActivityMonitor monitor, Action<IOutgoingMessage>? action = null )
        {
            int count = FlushAndClose( action, _highPriorityChannel.Reader! );
            count += FlushAndClose( action, _senderChannel.Reader );
            monitor.Trace( $"Cleanup {count} unsent messages for '{_transport.RemoteEndPointDescription}'." );

            static int FlushAndClose( Action<IOutgoingMessage>? action, ChannelReader<IOutgoingMessage?> r )
            {
                int count = 0;
                while( r.TryRead( out var m ) )
                {
                    if( m == null ) continue;
                    ++count;
                    action?.Invoke( m );
                    m.Release();
                }

                return count;
            }
        }

        internal bool Receive0Message( IActivityMonitor receiveMonitor, IncomingMessage m )
        {
            Throw.DebugAssert( m.Protocol == MessageProtocol.ZeroProtocol );
            Throw.DebugAssert( "The transport is trusted.", _transport.RemoteKeys != null );

            if( m == IncomingMessage.Empty )
            {
                // An empty message is not a real TransportMessage, it is the keep alive:
                // the other side worries about us because we did not send it any message for some time.
                // Let's reassure it. It is useless to use the high priority: if messages are being sent
                // we should not receive KeepAlive.
                receiveMonitor.Trace( $"Received KeepAlive request." );
                if( !TryEnqueue( IOutgoingMessage.EmptyAck ) )
                {
                    receiveMonitor.Warn( ActivityMonitor.Tags.ToBeInvestigated,
                                         $"Received a KeepAlive from '{_transport.RemoteEndPointDescription}' but our outgoing queue is full. This is weird!" ); ;
                }
                return true;
            }
            try
            {
                switch( m.Message.FirstSpan[0] )
                {
                    case ZeroProtocol.DRunGoodbye:
                        {
                            var goodbye = ZeroProtocol.ReadGoodbyeMessage( receiveMonitor, _transport, m );
                            if( goodbye == null )
                            {
                                // Fatal protocol error.
                                return false;
                            }
                            receiveMonitor.Info( $"Received GoodbyeMessage from '{_transport.RemoteEndPointDescription}': {goodbye}" );
                            int reconnectDelay;
                            switch( goodbye )
                            {
                                case GoodbyeMessage.Evicted:
                                    // When evicted, we MUST switch off the transport.
                                    // We are the initiator and the remote allows eviction: if we retry, we'll be accepted
                                    // and this will never end...
                                    _feature.RemoteSwitchedOff( goodbye );
                                    reconnectDelay = 0;
                                    break;
                                case GoodbyeMessage.SwitchedOff off:
                                    Throw.DebugAssert( "We are connected: we have a clock offset.", _feature.ClockOffset.HasValue );
                                    // HandleRemoteSwitchedOff returns 0 when no retry must be done (this is the OutgoingConnectionBackTask
                                    // retry convention). We adjust it here.
                                    reconnectDelay = OutgoingConnectionBackTask.HandleRemoteSwitchedOff( _feature, _feature.ClockOffset.Value, off );
                                    if( reconnectDelay == 0 ) reconnectDelay = int.MaxValue;
                                    break;
                                // PartyDestroyed and ApplicationIdentityShutdown: this can be transient (restart of the application
                                // or suppresion of a dynamic party to add it back with a different configuration).
                                // We don't switch of our remote, we just emit an issue.
                                default:
                                    reconnectDelay = 5;
                                    break;
                            }
                            _transportManager.OnRemoteSwitchedOffIssue( _feature, goodbye );
                            if( _transport.Condemn( goodbye ) )
                            {
                                _senderChannel.Writer.TryWrite( null );
                                // Ne delay here because there's nothing to do before killing the connection.
                                _transportManager.KillTransport( _transport, reconnectDelay );
                            }
                            return false;
                        }
                    default:
                        receiveMonitor.Warn( $"Received unknown '0 Protocol' message (Discriminator: '{m.Message.FirstSpan[0]}', Length: {m.Message.Length}). Ignoring it." );
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
