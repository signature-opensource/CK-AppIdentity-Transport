using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System.Diagnostics;

namespace CK.AppIdentity.BlobChannel
{
    public sealed class BlobChannelFeature : ChannelFeature
    {
        readonly PerfectEventSender<BlobChannelFeature, byte[]> _received;

        internal BlobChannelFeature( TransportFeature transport )
            : base( transport ) 
        {
            _received = new PerfectEventSender<BlobChannelFeature, byte[]>();
        }

        public PerfectEvent<BlobChannelFeature, byte[]> Received => _received.PerfectEvent;

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            Debug.Assert( c.Protocol.Version == 0 );
            return new Protocol( this, ref c );
        }

        sealed class Protocol : PeerProtocolHandler
        {
            readonly BlobChannelFeature _feature;

            public Protocol( BlobChannelFeature feature, ref CreateParameters createParameters )
                : base( ref createParameters )
            {
                _feature = feature;
            }

            protected override async ValueTask ReceiveAsync( TransportMessage message )
            {
            }
        }
    }

}
