using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// The <see cref="Transport"/> seen by message handlers.
    /// This hosts the outgoing message queue.
    /// </summary>
    public sealed partial class MessageEndPoint
    {
        static readonly UnboundedChannelOptions _senderChannelOptions = new() { SingleReader = true };

        Transport _transport;
        readonly TransportLayerFeature _feature;
        readonly Channel<TransportMessage> _senderChannel;

        internal MessageEndPoint( TransportManager transportManager, TransportLayerFeature feature, Transport transport )
        {
            _feature = feature;
            _senderChannel = Channel.CreateUnbounded<TransportMessage>( _senderChannelOptions );
            StartSend( transportManager, transport );
        }

        internal void Rebind( IActivityMonitor monitor, TransportManager transportManager, Transport transport )
        {
            Debug.Assert( transportManager.IsInLoop( monitor ) );
            Debug.Assert( _transport.IsCondemned );
            StartSend( transportManager, transport );
        }

        [MemberNotNull( nameof( _transport ) )]
        void StartSend( TransportManager transportManager, Transport transport )
        {
            _transport = transport;
            _transport.SetMessageEndPoint( this );
            Task.Run( () => RunSend( transportManager, transport, _senderChannel.Reader ) );
        }

        internal Transport Transport => _transport;

        /// <summary>
        /// Gets the feature that manages this end point.
        /// </summary>
        public TransportLayerFeature Feature => _feature;

        /// <summary>
        /// Gets the remote end point description.
        /// This doesn't identify a remote (different remotes can be exposed by the same external address on a network).
        /// </summary>
        public string EndPointDescription => _transport.RemoteEndPointDescription;

        /// <summary>
        /// Gets whether this endpoint is connected.
        /// </summary>
        public bool IsConnected => !_transport.Lifetime.IsCancellationRequested;

        /// <summary>
        /// Attempts to send the message to the transport queue.
        /// </summary>
        /// <param name="message">The message to enqueue.</param>
        /// <returns>true if the message has been enqueued.</returns>
        public bool TryEnqueue( TransportMessage message ) => _senderChannel.Writer.TryWrite( message );

        /// <summary>
        /// Waits for a space to enqueue a message.
        /// </summary>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to cancel the wait operation.</param>
        /// <returns>
        /// True when a new message can be enqueued, false if the connection has been lost.
        /// </returns>
        public ValueTask<bool> WaitToEnqueueAsync( CancellationToken cancellationToken = default ) => _senderChannel.Writer.WaitToWriteAsync( cancellationToken );

        /// <summary>
        /// Asynchronously enqueues a message.
        /// </summary>
        /// <param name="message">The message to enqueue.</param>
        /// <param name="cancellationToken">Optional <see cref="CancellationToken"/>.</param>
        /// <returns>
        /// True if the message has been be enqueued, false if the connection has been lost.
        /// </returns>
        public async ValueTask<bool> EnqueueAsync( TransportMessage message, CancellationToken cancellationToken = default )
        {
            try
            {
                await _senderChannel.Writer.WriteAsync( message, cancellationToken ).ConfigureAwait( false );
                return true;
            }
            catch( ChannelClosedException )
            {
                return false;
            }
        }

        static async void RunSend( TransportManager transportManager,
                                   Transport transport,
                                   ChannelReader<TransportMessage> reader )
        {
            try
            {
                while( await reader.WaitToReadAsync().ConfigureAwait( false ) )
                {
                    if( reader.TryPeek( out var m ) )
                    {
                        if( !await transport.SendAsync( m ).ConfigureAwait( false ) )
                        {
                            transportManager.Logger.Trace( $"Canceled send for '{transport.RemoteEndPointDescription}'." );
                            break;
                        }
                        var consumed = reader.TryRead( out var m2 );
                        Debug.Assert( consumed && m == m2 );
                        m.Dispose();
                    }
                }
            }
            catch( Exception ex )
            {
                Debug.Assert( ex is not ChannelClosedException, "The way we use it avoids to rely on the ChannelClosedException." );
                transportManager.TransportErrorSendMessage( transport, ex );
            }
        }

        internal void ClearPendingOutgoingMessages( IActivityMonitor monitor, Action<TransportMessage>? action = null )
        {
            var r = _senderChannel.Reader;
            int count = 0;
            while( r.TryRead( out var m ) )
            {
                ++count;
                action?.Invoke( m );
                m.Dispose();
            }
            monitor.Trace( $"Cleanup {count} unsent messages for '{EndPointDescription}'." ); 
        }
    }
}
