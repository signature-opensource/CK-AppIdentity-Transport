using CK.AppIdentity.BlobChannel;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading.Tasks;

namespace CK.AppIdentity.PocoChannel
{
    /// <summary>
    /// Poco channel is a opt-out feature: to deactivate it, use "DisallowFeatures" with "PocoChannel".
    /// </summary>
    public sealed class PocoChannelFeatureDriver : ChannelFeatureDriver<PocoChannelFeature>
    {
        readonly PocoDirectory _pocoDirectory;

        public PocoChannelFeatureDriver( ApplicationIdentityService s, PocoDirectory pocoDirectory )
            : base( s, isAllowedByDefault: true )
        {
            _pocoDirectory = pocoDirectory;
        }

        /// <inheritdoc/>
        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out PocoChannelFeature? channel )
        {
            channel = new PocoChannelFeature( transport, _pocoDirectory );
            return true;
        }
    }
}
