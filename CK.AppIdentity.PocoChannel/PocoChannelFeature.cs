using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.PocoChannel
{
    public class PocoChannelFeature : ChannelFeature
    {

        public PocoChannelFeature( TransportLayerFeature transportFeature )
            : base( transportFeature )
        {
        }
    }
}
