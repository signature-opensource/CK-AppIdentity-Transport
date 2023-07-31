using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Simple channel. This is more a sample than a useful channel.
    /// Received bytes are exposed by <see cref="Received"/> event.
    /// </summary>
    public sealed partial class BlobChannelFeature : ChannelFeature
    {
        readonly PerfectEventSender<BlobChannelFeature, byte[]> _received;

        internal BlobChannelFeature( TransportFeature transport )
            : base( transport ) 
        {
            _received = new PerfectEventSender<BlobChannelFeature, byte[]>();
        }

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        /// <summary>
        /// Gets an event for the bytes received.
        /// </summary>
        public PerfectEvent<BlobChannelFeature, byte[]> Received => _received.PerfectEvent;

        /// <summary>
        /// Tries to send the data to the remote.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>True if data has been successfully sent.</returns>
        public bool TrySend( byte[] data )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( data );
                if( h.TryEnqueue( message ) ) return true;
                message.Release();
            }
            return false;
        }

        /// <summary>
        /// Tries to send the data to the remote.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>True if data has been successfully sent.</returns>
        public async ValueTask<bool> TrySendAsync( byte[] data )
        {
            Throw.CheckArgument( data.Length > 0 );
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( data );
                if( await h.TryEnqueueAsync( message ) ) return true;
                message.Release();
            }
            return false;
        }

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            Throw.DebugAssert( c.Protocol.Version == 0 );
            return new Protocol( this, ref c );
        }
    }

}
