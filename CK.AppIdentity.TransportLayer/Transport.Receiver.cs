using CK.Core;
using System.Diagnostics;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    public abstract partial class Transport
    {
        IMessageHandler[]? _outputs;

        internal IReadOnlyList<IMessageHandler>? Handlers => _outputs;

        /// <summary>
        /// Binds the <see cref="Handlers"/> and starts the reading loop that
        /// dispatch the incoming messages to the appropriate receiver based on
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
        /// <param name="outputs">The <see cref="Handlers"/>.</param>
        internal void StartReceive( IActivityMonitor monitor,
                                    TransportManager transportManager,
                                    MessageProtocolMap protocols,
                                    IMessageHandler[] outputs )
        {
            Debug.Assert( transportManager.IsInLoop( monitor ) );
            Debug.Assert( protocols.IsValid );
            Debug.Assert( outputs.Length == protocols.Protocols.Count );
            Debug.Assert( !_receiveFactory.AllowedProtocols.IsValid );
            _receiveFactory.SetBoundMode( protocols );
            Task.Run( () => RunReceive( transportManager, this, outputs ) );
        }

        static async void RunReceive( TransportManager transportManager,
                                      Transport transport,
                                      IMessageHandler[] outputs )
        {
            Debug.Assert( transport.EndPoint != null );
            var receiveFactory = transport._receiveFactory;
            var reader = transport._reader;
            try
            {
                for(; ; )
                {
                    var m = await receiveFactory.DoReadAsync( reader, int.MaxValue, transport.Lifetime );
                    if( m.Protocol == MessageProtocol.ZeroProtocol )
                    {
                        if( m == TransportMessage.Empty )
                        {
                            // An empty message (a single 0 byte) is not a real TransportMessage, it is the keep alive:
                            // the other side worries about us because we did not send it any message for some time.
                            // Let's reassure it.
                            transportManager.TransportKeepAliveReceived( transport );
                        }
                        else if( m == TransportMessage.Canceled )
                        {
                            transportManager.Logger.Trace( $"Canceled received for '{transport.RemoteEndPointDescription}'." );
                            break;
                        }
                        else if( m == TransportMessage.Invalid )
                        {
                            transportManager.TransportReceiveErrorMessage( transport, null );
                            break;
                        }
                        else
                        {
                            transport.EnsureZeroProtocol().Receive( m );
                        }
                    }
                    else
                    {
                        Debug.Assert( receiveFactory._lastProtocolNumber > 0 && receiveFactory._lastProtocolNumber <= outputs.Length );
                        await outputs[receiveFactory._lastProtocolNumber - 1].ReceiveAsync( transport.EndPoint, m ).ConfigureAwait( false );
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
