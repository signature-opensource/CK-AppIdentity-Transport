using CK.Core;
using System.Diagnostics;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        /// <summary>
        /// Gets the handlers to which incoming messages are routed.
        /// </summary>
        internal IReadOnlyList<PeerProtocolHandler>? Handlers => _handlers;

        /// <summary>
        /// Binds the <see cref="Handlers"/> and starts the reading loop that
        /// dispatch the incoming messages to the appropriate handler based on
        /// the protocol number.
        /// <para>
        /// This is the last step that "activates" a Transport: the protocols have been
        /// negotiated and the channels have setup a dedicated receiver for every protocols.
        /// </para>
        /// <para>
        /// The receiving loop ends as soon as the <see cref="Lifetime"/> is signaled.
        /// </para>
        /// </summary>
        /// <param name="monitor">The transport manager monitor.</param>
        /// <param name="transportManager">The transport manager.</param>
        /// <param name="protocols">The negotiated protocols from which the receivers have been obtained.</param>
        /// <param name="handlers">The <see cref="Handlers"/>.</param>
        internal void StartReceive( IActivityMonitor monitor,
                                    TransportManager transportManager,
                                    MessageProtocolMap protocols,
                                    PeerProtocolHandler[] handlers )
        {
            Debug.Assert( transportManager.IsInLoop( monitor ) );
            Debug.Assert( protocols.IsValid );
            Debug.Assert( handlers.Length == protocols.Protocols.Count );
            Debug.Assert( !_receiveFactory.AllowedProtocols.IsValid );
            _receiveFactory.SetBoundMode( protocols );
            _handlers = handlers;
            Task.Run( () => RunReceive( transportManager, this, handlers ) );
        }

        static async void RunReceive( TransportManager transportManager,
                                      Transport transport,
                                      PeerProtocolHandler[] handlers )
        {
            Debug.Assert( transport.OutgoingMessageQueue != null );
            var receiveFactory = transport._receiveFactory;
            var reader = transport._reader;
            try
            {
                for(; ; )
                {
                    var m = await receiveFactory.DoReadAsync( reader, int.MaxValue, transport.Lifetime );
                    if( m.Protocol == MessageProtocol.ZeroProtocol )
                    {
                        // Handles cancellation and error.
                        if( m == TransportMessage.Canceled )
                        {
                            transportManager.Logger.Trace( $"Canceled received for '{transport.RemoteEndPointDescription}'." );
                            break;
                        }
                        if( m == TransportMessage.Invalid )
                        {
                            transportManager.TransportReceiveErrorMessage( transport, null );
                            break;
                        }
                        // Handles KeepAlive directly without instantiating the ZeroProtocol handler.
                        if( m == TransportMessage.Empty )
                        {
                            // An empty message (a single 0 byte) is not a real TransportMessage, it is the keep alive:
                            // the other side worries about us because we did not send it any message for some time.
                            // Let's reassure it.
                            Debug.Assert( transport.OutgoingMessageQueue != null );
                            if( !transport.OutgoingMessageQueue.TryEnqueue( TransportMessage.EmptyAck ) )
                            {
                                transportManager.Logger.Warn( $"Received a KeepAlive from '{transport.RemoteEndPointDescription}' but our outgoing queue is full. This is weird!" );
                            }
                        }
                        else if( m == TransportMessage.EmptyAck )
                        {
                            // The empty message acknowledgment: the IncomingMessageFactory.LastReceived has been updated.
                            // we have nothing to do.
                        }
                        else
                        {
                            transport.EnsureZeroProtocol().Receive( transportManager, m );
                        }
                    }
                    else
                    {
                        Debug.Assert( receiveFactory._lastProtocolNumber > 0 && receiveFactory._lastProtocolNumber <= handlers.Length );
                        await handlers[receiveFactory._lastProtocolNumber - 1].ReceiveAsync( m ).ConfigureAwait( false );
                    }
                }
            }
            catch( Exception ex )
            {
                transportManager.TransportReceiveErrorMessage( transport, ex );
            }
        }

    }

}
