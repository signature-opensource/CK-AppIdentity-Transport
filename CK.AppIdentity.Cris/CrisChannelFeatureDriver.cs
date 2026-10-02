using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;

public sealed class CrisChannelFeatureDriver : ChannelFeatureDriver<CrisChannelFeature>
{
    readonly PocoDirectory _pocoDirectory;
    readonly IDIContainer<AppIdentityDIContainerDefinition.Data> _endpoint;
    readonly CrisExecutionHost _executionHost;

    public CrisChannelFeatureDriver( TransportFeatureDriver transport,
                                     PocoDirectory pocoDirectory,
                                     IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint,
                                     CrisExecutionHost executionHost )
        : base( transport, isAllowedByDefault: true )
    {
        _pocoDirectory = pocoDirectory;
        _endpoint = endpoint;
        _executionHost = executionHost;
    }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisChannelFeature? channel )
    {
        channel = new CrisChannelFeature( transport, _pocoDirectory, _executionHost, _endpoint );
        return true;
    }
}
