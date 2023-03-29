using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    public sealed class BlobChannelFeature : ChannelFeature
    {
        internal BlobChannelFeature( TransportLayerFeature transport )
            : base( transport ) 
        {
        }

    }

}
