using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Blob channels is a opt-in feature: to activate it, "AllowFeatures" of the remote must contain "BlobChannel".
    /// </summary>
    public sealed class BlobChannelFeatureDriver : ChannelFeatureDriver<BlobChannelFeature>
    {
        public BlobChannelFeatureDriver( ApplicationIdentityService s, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( s, false )
        {
        }

        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportLayerFeature transport, out BlobChannelFeature? channel )
        {
            channel = new BlobChannelFeature( transport );
            return true;
        }
    }

}
