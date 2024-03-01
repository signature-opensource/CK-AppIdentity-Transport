using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        /// <summary>
        /// Gets the handlers to which incoming messages are routed.
        /// This is set by StartReceiveAsync and used by the <see cref="Controller"/>.
        /// </summary>
        internal IReadOnlyList<PeerProtocolHandler>? Handlers => _receiveHandlers;

        /// <summary>
        /// Used during the initial negotiation.
        /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
        /// <see cref="IsCondemned"/> has been set, in such case <see cref="IncomingMessage.Canceled"/> is returned.
        /// </summary>
        /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
        /// <returns>
        /// A message that may be one of the special messages <see cref="IncomingMessage.Invalid"/>, <see cref="IncomingMessage.Canceled"/>,
        /// <see cref="IncomingMessage.Empty"/> or <see cref="IncomingMessage.EmptyAck"/>.
        /// </returns>
        internal Task<IncomingMessage> ReadNextAsync( int maxMessageLength = int.MaxValue )
        {
            Throw.DebugAssert( maxMessageLength > 0 );
            Throw.DebugAssert( "Not started yet.", _controller == null );
            return _receiveFactory.DoReadAsync( _reader, maxMessageLength, _lifeTime.Token );
        }

        /// <summary>
        /// Binds the <see cref="Handlers"/> and starts the reading loop that dispatches the incoming messages to the
        /// appropriate handler based on the message protocol number.
        /// <para>
        /// This is the last step that makes a Transport ready to receive messages: the protocols
        /// have been negotiated and the channels have setup a dedicated receiver for every protocols.
        /// </para>
        /// <para>
        /// The receiving loop ends as soon as the <see cref="Lifetime"/> is signaled or if a read error occurs
        /// that triggers the condemnation of this transport: this loop is run once and only once.
        /// </para>
        /// </summary>
        /// <param name="receiveMonitor">The existing and available feature's receive monitor or null if a new one must be created.</param>
        /// <param name="transportManager">The transport manager.</param>
        /// <param name="protocols">The negotiated protocols from which the handlers have been obtained.</param>
        /// <param name="handlers">The <see cref="Handlers"/>.</param>
        /// <returns>The receive monitor that should be reused.</returns>
        internal Task<IActivityMonitor> StartReceiveAsync( IActivityMonitor? receiveMonitor,
                                                           TransportManager transportManager,
                                                           MessageProtocolMap protocols,
                                                           PeerProtocolHandler[] handlers )
        {
            Throw.DebugAssert( protocols.IsValid );
            Throw.DebugAssert( handlers.Length == protocols.Protocols.Count );
            _receiveFactory.SetAllowedProtocols( protocols );
            _receiveHandlers = handlers;
            // The LifeTime drives the receive CTS: this is a safety net.
            // There is no need to unregister the callback here.
            _receiveCTS = new CancellationTokenSource();
            _lifeTime.Token.UnsafeRegister( static r => Unsafe.As<CancellationTokenSource>( r )!.Cancel(), _receiveCTS );
            return Task.Run( () => RunReceiveAsync( receiveMonitor, transportManager, this ) );
        }

        static async Task<IActivityMonitor> RunReceiveAsync( IActivityMonitor? receiveMonitor,
                                                             TransportManager transportManager,
                                                             Transport transport )
        {
            Throw.DebugAssert( transport.Controller != null && transport._receiveCTS != null && transport._receiveHandlers != null );
            receiveMonitor ??= new ActivityMonitor( $"Receive loop for '{transport.Controller.Feature.Party.FullName}'." );
            // Captures used variables:
            IncomingMessageFactory receiveFactory = transport._receiveFactory;
            Func<Memory<byte>, CancellationToken, ValueTask> reader = transport._reader;
            CancellationToken receiveToken = transport._receiveCTS.Token;
            PeerProtocolHandler[] handlers = transport._receiveHandlers;
            using var log = receiveMonitor.OpenInfo( $"Start receiving messages from '{transport}'." );
            try
            {
                for(; ; )
                {
                    var m = await receiveFactory.DoReadAsync( reader, int.MaxValue, receiveToken );
                    if( m.Protocol == MessageProtocol.ZeroProtocol )
                    {
                        // Handles Canceled and Invalid messages.
                        if( !m.IsValid )
                        {
                            if( m == IncomingMessage.Canceled )
                            {
                                // The receiveCTS has been signaled.
                                receiveMonitor.Trace( $"Canceled message received." );
                                break;
                            }
                            if( m == IncomingMessage.Invalid )
                            {
                                // The message was invalid. This is a serious error: kill
                                // the transport as if an exception occurred and like the exception case
                                // retry asap if we are an outgoing connection.
                                receiveMonitor.Error( $"Invalid message received." );
                                transportManager.KillTransport( transport, 0 );
                                break;
                            }
                        }
                        // Handles KeepAlive acknowledgment directly without bothering the controller.
                        if( m == IncomingMessage.EmptyAck )
                        {
                            // The empty message acknowledgment: the IncomingMessageFactory.LastReceived has been updated.
                            // we have nothing to do.
                            receiveMonitor.Trace( $"Received KeepAlive acknowledgment." );
                        }
                        else
                        {
                            // A bye-bye message or a fatal protocol error occurred.
                            // It is up to the Receive0Message to send a KillTransport message to the
                            // TransportManager when false is returned.
                            if( !transport.Controller.Receive0Message( receiveMonitor, m ) )
                            {
                                // We don't have a "KillTransportRequested" flag on a Transport.
                                break;
                            }
                        }
                    }
                    else
                    {
                        int n = m.GetProtocolNumber();
                        Throw.DebugAssert( n > 0 && n <= handlers.Length );
                        await handlers[n - 1].ReceiveAsync( receiveMonitor, m ).ConfigureAwait( false );
                    }
                }
            }
            catch( Exception ex )
            {
                receiveMonitor.Error( $"While receiving on '{transport}'.", ex );
                // Retrying asap if we are an outgoing connection.
                transportManager.KillTransport( transport, 0 );
            }
            return receiveMonitor;
        }

    }

}
