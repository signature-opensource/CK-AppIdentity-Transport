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
        public PocoChannelFeatureDriver( ApplicationIdentityService s, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( s, true )
        {
        }

        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out PocoChannelFeature? channel )
        {
            channel = new PocoChannelFeature( transport );
            return true;
        }
    }
}
