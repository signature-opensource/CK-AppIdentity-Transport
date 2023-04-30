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
    public sealed class CrisChannelFeatureDriver : ChannelFeatureDriver<CrisChannelFeature>
    {
        readonly PocoDirectory _pocoDirectory;
        readonly CrisChannelExecutor _executor;
        readonly IAuthenticationInfoTokenService _tokenService;

        public CrisChannelFeatureDriver( TransportFeatureDriver transport,
                                         PocoDirectory pocoDirectory,
                                         CrisChannelExecutor executor,
                                         IAuthenticationInfoTokenService tokenService )
            : base( transport, isAllowedByDefault: true )
        {
            _pocoDirectory = pocoDirectory;
            _executor = executor;
            _tokenService = tokenService;
        }

        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisChannelFeature? channel )
        {
            channel = new CrisChannelFeature( transport, _pocoDirectory, _executor, _tokenService );
            return true;
        }
    }
}
