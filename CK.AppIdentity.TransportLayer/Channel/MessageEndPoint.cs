using CK.Core;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Channels;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// The <see cref="Transport"/> seen by message handlers.
    /// This hosts the outgoing message queue. When in multiple listening mode, these end points are chained.
    /// </summary>
    public sealed partial class MessageEndPoint
    {
        static readonly UnboundedChannelOptions _senderChannelOptions = new() { SingleReader = true };
        // Transport can be rebound when ListeningMode is Default: either we are a client or a server listening to a single remote.
        Transport _transport;
        internal MessageEndPoint? _prevEndPoint;
        internal MessageEndPoint? _nextEndPoint;
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
            Debug.Assert( _feature.ListeningMode == ListeningMode.Default );
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

        internal void OnTransportSetCondemned()
        {
            // We don't close a single transport connection: this preserves
            // the message queue.
            if( _feature.ListeningMode != ListeningMode.Default )
            {
                _senderChannel.Writer.TryComplete();
            }
        }

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
        /// Attempts to send the message to the transport queues.
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
        public async ValueTask<bool> Enqueue( TransportMessage message, CancellationToken cancellationToken = default )
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

        /// <summary>
        /// This is called when a multiple listening endpoint is disconnected: unsent messages are if possible transfered
        /// to other endpoints or disposed. If the party is being destroyed, it is <see cref="ClearPendingOutgoingMessages(IActivityMonitor)"/>
        /// that is called on all endpoints (including <see cref="ListeningMode.Default"/> one).
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        internal void HandlePendingOutgoingMessages( IActivityMonitor monitor )
        {
            Debug.Assert( _feature.ListeningMode != ListeningMode.Default );
            var r = _senderChannel.Reader;
            IDisposableGroup? warnGroup = null;
            int zeroCount = 0;
            int lost = 0;
            int requeued = 0;
            while( r.TryRead( out var m ) )
            {
                warnGroup ??= monitor.OpenWarn( $"Handling unsent messages for disconnected '{EndPointDescription}'." );
                if( m.Protocol == MessageProtocol.ZeroProtocol )
                {
                    zeroCount++;
                    continue;
                }
                Debug.Assert( _transport.Handlers != null, "There cannot be sent messages before the Transport.StartReceive has been called." );
                int protocolNumber = _transport.NegotiatedProtocols.GetProtocolNumber( m.Protocol );
                if( !_transport.Handlers[protocolNumber].TryEnqueueUnsentMessages( m ) )
                {
                    ++lost;
                    monitor.Error( $"Unable to re-queue message for protocol '{m.Protocol}'. Message is lost." );
                    m.Dispose();
                }
                else
                {
                    ++requeued;
                }
            }
            if( warnGroup != null )
            {
                if( zeroCount > 0 ) monitor.Warn( $"Lost {zeroCount} '0 protocol' messages." );
                if( lost == 0 )
                {
                    monitor.Info( $"{requeued} messages have been successfully transfered to other endpoints." );
                }
                else
                {
                    monitor.CloseGroup( $"Lost {lost} out of {requeued+lost} messages." );
                }
            }
        }

        internal void ClearPendingOutgoingMessages( IActivityMonitor monitor )
        {
            var r = _senderChannel.Reader;
            int count = 0;
            while( r.TryRead( out var m ) )
            {
                ++count;
                m.Dispose();
            }
            monitor.Trace( $"Cleanup {count} unsent messages for '{EndPointDescription}'." ); 
        }
    }
}
