using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.PocoChannel
{
    public class PocoChannelFeature : ChannelFeature
    {

        public PocoChannelFeature( TransportFeature transportFeature )
            : base( transportFeature )
        {
        }

        protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
        {
            throw new NotImplementedException();
        }
    }
}
