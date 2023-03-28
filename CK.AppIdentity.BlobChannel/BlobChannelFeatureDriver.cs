using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Blob channels is a opt-in feature: to activate it, "AllowFeatures" of the remote must contain "BlobChannel".
    /// </summary>
    public sealed class BlobChannelFeatureDriver : MessageProtocolFeatureDriver<BlobChannelFeature>
    {
        public BlobChannelFeatureDriver( ApplicationIdentityService s, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( s, messageProtocolDirectory, false )
        {
        }

        protected override bool PlugFeature( FeatureLifetimeContext context,
                                             IRemoteParty party,
                                             TransportFeature transport,
                                             MessageProtocolDirectoryService messageProtocolDirectory )
        {
            var f = new BlobChannelFeature( transport, messageProtocolDirectory );
            party.AddFeature( f );
            return true;
        }

    }

}
