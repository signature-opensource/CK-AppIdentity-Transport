using CK.AppIdentity.BlobChannel;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public sealed class CrisEndPointChannelFeatureDriver : ChannelFeatureDriver<CrisEndPointFeature>
    {
        readonly PocoDirectory _pocoDirectory;
        readonly IServiceProvider _serviceProvider;

        public CrisEndPointChannelFeatureDriver( TransportFeatureDriver transport, PocoDirectory pocoDirectory, IServiceProvider serviceProvider )
            : base( transport, isAllowedByDefault: true )
        {
            _pocoDirectory = pocoDirectory;
            _serviceProvider = serviceProvider;
        }

        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisEndPointFeature? channel )
        {
            channel = new CrisEndPointFeature( transport, _pocoDirectory, _serviceProvider );
            return true;
        }
    }
}
