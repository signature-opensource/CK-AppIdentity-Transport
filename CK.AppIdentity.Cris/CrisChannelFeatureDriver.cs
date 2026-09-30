using CK.AppIdentity.TransportLayer;
using CK.Auth;
using CK.Core;
using CK.Cris;
using System.Linq;

namespace CK.AppIdentity.Cris;

public sealed class CrisChannelFeatureDriver : ChannelFeatureDriver<CrisChannelFeature>
{
    readonly PocoDirectory _pocoDirectory;
    readonly IDIContainer<AppIdentityEndpointDefinition.Data> _endpoint;
    readonly CrisExecutionHost _executionHost;
    readonly ICrisAuthCenter? _crisAuthCenter;
    readonly IAuthenticationInfoTokenService _tokenService;

    public CrisChannelFeatureDriver( TransportFeatureDriver transport,
                                     PocoDirectory pocoDirectory,
                                     IDIContainer<AppIdentityEndpointDefinition.Data> endpoint,
                                     CrisExecutionHost executionHost,
                                     ICrisAuthCenter? crisAuthCenter,
                                     IAuthenticationInfoTokenService tokenService )
        : base( transport, isAllowedByDefault: true )
    {
        _pocoDirectory = pocoDirectory;
        _endpoint = endpoint;
        _executionHost = executionHost;
        _crisAuthCenter = crisAuthCenter;
        _tokenService = tokenService;
    }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisChannelFeature? channel )
    {
        channel = new CrisChannelFeature( transport, _pocoDirectory, _endpoint, _executionHost, _crisAuthCenter, _tokenService );
        return true;
    }
}
