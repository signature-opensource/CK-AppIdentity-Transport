using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    /// <summary>
    /// Blob channels is a opt-in feature: to activate it, "AllowFeatures" of the remote must contain "BlobChannel".
    /// <para>
    /// The protocol name is inferred from this type name that must be suffixed by "ChannelFeatureDriver": the
    /// <see cref="ChannelFeature.BaseProtocolName"/> is automatically "Blob" (and the <see cref="ApplicationIdentityFeatureDriver.FeatureName"/>
    /// is by design "BlobChannel".
    /// </para>
    /// </summary>
    public sealed class BlobChannelFeatureDriver : ChannelFeatureDriver<BlobChannelFeature>
    {
        /// <summary>
        /// Initializes a new singleton service that manages the <see cref="BlobChannelFeature"/> of <see cref="IRemoteParty"/>.
        /// </summary>
        /// <param name="transport">The transport feature.</param>
        public BlobChannelFeatureDriver( TransportFeatureDriver transport )
            : base( transport, isAllowedByDefault: false )
        {
        }

        /// <inheritdoc/>
        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out BlobChannelFeature? channel )
        {
            channel = new BlobChannelFeature( transport );
            return true;
        }
    }

}
