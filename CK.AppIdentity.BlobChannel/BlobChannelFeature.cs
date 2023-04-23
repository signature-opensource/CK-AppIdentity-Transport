using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

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

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        public PerfectEvent<BlobChannelFeature, byte[]> Received => _received.PerfectEvent;

        public bool TrySend( byte[] data )
        {
            Throw.CheckArgument( data.Length > 0 );
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( data );
                if( h.TryEnqueue( message ) ) return true;
                message.Dispose();
            }
            return false;
        }

        public async ValueTask<bool> TrySendAsync( byte[] data )
        {
            Throw.CheckArgument( data.Length > 0 );
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( data );
                if( await h.TryEnqueueAsync( message ) ) return true;
                message.Dispose();
            }
            return false;
        }

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            Debug.Assert( c.Protocol.Version == 0 );
            return new Protocol( this, ref c );
        }

        protected override void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
        {
        }

        sealed class Protocol : PeerProtocolHandler
        {
            readonly BlobChannelFeature _feature;

            public Protocol( BlobChannelFeature feature, ref CreateParameters createParameters )
                : base( ref createParameters )
            {
                _feature = feature;
            }

            public TransportMessage CreateMessage( byte[] data )
            {
                var message = MessageFactory.Create( bytes => bytes.Write( data ) );
                message.Source = data;
                return message;
            }

            protected override async ValueTask ReceiveAsync( IActivityMonitor monitor, TransportMessage message )
            {
                var payload = message.Message.ToArray();
                message.Dispose();
                await _feature._received.SafeRaiseAsync( monitor, _feature, payload );
            }
        }
    }

}
