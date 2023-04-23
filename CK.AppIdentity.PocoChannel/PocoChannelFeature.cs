using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.PerfectEvent;
using System.Runtime.CompilerServices;
using System.Text;

namespace CK.AppIdentity.PocoChannel
{
    public partial class PocoChannelFeature : ChannelFeature
    {
        readonly PerfectEventSender<PocoChannelFeature, IPoco?> _received;
        readonly PocoDirectory _pocoDirectory;

        public PocoChannelFeature( TransportFeature transportFeature, PocoDirectory pocoDirectory )
            : base( transportFeature )
        {
            _received = new PerfectEventSender<PocoChannelFeature, IPoco?>();
            _pocoDirectory = pocoDirectory;
        }

        new Protocol? CurrentHandler => Unsafe.As<Protocol?>( base.CurrentHandler );

        public bool TrySend( IPoco? poco, bool isResponse = false )
        {
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( poco );
                if( isResponse ? h.TryEnqueueResponse( message ) : h.TryEnqueue( message ) )
                {
                    return true;
                }
                message.Dispose();
            }
            return false;
        }

        public async ValueTask<bool> TrySendAsync( IPoco? poco, bool isResponse = false )
        {
            Throw.CheckNotNullArgument( poco );
            var h = CurrentHandler;
            if( h != null )
            {
                var message = h.CreateMessage( poco );
                if( isResponse )
                {
                    if( h.TryEnqueueResponse( message ) )
                    {
                        return true;
                    }
                }
                else if( await h.TryEnqueueAsync( message ) )
                {
                    return true;
                }
                message.Dispose();
            }
            return false;
        }

        public PerfectEvent<PocoChannelFeature, IPoco?> ReceivedPoco => _received.PerfectEvent;

        public ValueTask<IPoco?> LoadAsync( in StoredPocoHandle handle )
        {
            return ValueTask.FromResult<IPoco?>( null );
        }

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            return new Protocol( this, ref c );
        }

        protected override void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
        {
        }

    }
}
