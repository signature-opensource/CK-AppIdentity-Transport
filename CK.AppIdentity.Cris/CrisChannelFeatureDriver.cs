using CK.AppIdentity.BlobChannel;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
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
        readonly IEndpointType<AppIdentityEndpointDefinition.Data> _endpoint;
        readonly CrisExecutionHost _executionHost;
        readonly IAuthenticationInfoTokenService _tokenService;

        public CrisChannelFeatureDriver( TransportFeatureDriver transport,
                                         PocoDirectory pocoDirectory,
                                         IEndpointType<AppIdentityEndpointDefinition.Data> endpoint,
                                         CrisExecutionHost executionHost,
                                         IAuthenticationInfoTokenService tokenService )
            : base( transport, isAllowedByDefault: true )
        {
            _pocoDirectory = pocoDirectory;
            _endpoint = endpoint;
            _executionHost = executionHost;
            _tokenService = tokenService;
        }

        protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisChannelFeature? channel )
        {
            channel = new CrisChannelFeature( transport, _pocoDirectory, _endpoint, _executionHost, _tokenService );
            return true;
        }
    }
}
