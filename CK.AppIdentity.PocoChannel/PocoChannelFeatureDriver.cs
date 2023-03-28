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
    public sealed class PocoChannelFeatureDriver : MessageProtocolFeatureDriver<PocoChannelFeature>
    {
        public PocoChannelFeatureDriver( ApplicationIdentityService s, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( s, messageProtocolDirectory, true )
        {
        }

        protected override bool PlugFeature( FeatureLifetimeContext context,
                                             IRemoteParty party,
                                             TransportFeature transport,
                                             MessageProtocolDirectoryService messageProtocolDirectory )
        {
            var f = new PocoChannelFeature( transport, messageProtocolDirectory );
            party.AddFeature( f );
            return true;
        }
    }
}
