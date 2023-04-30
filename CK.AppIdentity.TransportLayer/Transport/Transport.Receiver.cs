using CK.Core;
using System.Diagnostics;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        /// <summary>
        /// Gets the handlers to which incoming messages are routed.
        /// This is set by StartReceiveAsync and used by the <see cref="Controller"/>.
        /// </summary>
        internal IReadOnlyList<PeerProtocolHandler>? Handlers => _handlers;

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
            Debug.Assert( protocols.IsValid );
            Debug.Assert( handlers.Length == protocols.Protocols.Count );
            _receiveFactory.SetAllowedProtocols( protocols );
            _handlers = handlers;
            return Task.Run( () => RunReceiveAsync( receiveMonitor, transportManager, this, handlers ) );
        }

        static async Task<IActivityMonitor> RunReceiveAsync( IActivityMonitor? receiveMonitor,
                                                             TransportManager transportManager,
                                                             Transport transport,
                                                             PeerProtocolHandler[] handlers )
        {
            Debug.Assert( transport.Controller != null );
            receiveMonitor ??= new ActivityMonitor( $"Receive loop for '{transport.Controller.Feature.Party.FullName}'." );
            var receiveFactory = transport._receiveFactory;
            var reader = transport._reader;
            using var log = receiveMonitor.OpenInfo( $"Receiving messages from '{transport}'." );
            try
            {
                for(; ; )
                {
                    var m = await receiveFactory.DoReadAsync( reader, int.MaxValue, transport.Lifetime );
                    if( m.Protocol == MessageProtocol.ZeroProtocol )
                    {
                        // Handles Canceled and Invalid messages.
                        if( m == TransportMessage.Canceled )
                        {
                            // The transport.LifeTime has been signaled: the transport has been
                            // killed.
                            receiveMonitor.Trace( $"Canceled message received." );
                            break;
                        }
                        if( m == TransportMessage.Invalid )
                        {
                            // The message was invalid. This is a serious error: kill
                            // the transport as if an exception occurred.
                            receiveMonitor.Error( $"Invalid message received." );
                            transportManager.KillTransport( transport );
                            break;
                        }
                        // Handles KeepAlive acknowledgment directly without bothering the controller.
                        if( m == TransportMessage.EmptyAck )
                        {
                            // The empty message acknowledgment: the IncomingMessageFactory.LastReceived has been updated.
                            // we have nothing to do.
                            receiveMonitor.Trace( $"Received KeepAlive acknowledgment." );
                        }
                        else
                        {
                            // A bye-bye message or a fatal protocol error occurred.
                            if( !transport.Controller.Receive0Message( receiveMonitor, m ) )
                            {
                                break;
                            }
                        }
                    }
                    else
                    {
                        int n = m.GetProtocolNumber();
                        Debug.Assert( n > 0 && n <= handlers.Length );
                        await handlers[n - 1].ReceiveAsync( receiveMonitor, m ).ConfigureAwait( false );
                    }
                }
            }
            catch( Exception ex )
            {
                receiveMonitor.Error( $"While receiving on '{transport}'.", ex );
                transportManager.KillTransport( transport );
            }
            return receiveMonitor;
        }

    }

}
