using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System.Collections.Generic;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Creates the <see cref="CrisChannelFeature"/> on each remote that has a <see cref="TransportFeature"/>.
/// </summary>
// The channel exchanges commands, events and results as Json.
[AlsoRegisterType<ICrisCallResult, CommonPocoJsonSupport, ICrisCallEnvelope>]
public sealed class CrisChannelFeatureDriver : ChannelFeatureDriver<CrisChannelFeature>
{
    readonly PocoDirectory _pocoDirectory;
    readonly IPocoFactory<ICrisResultError> _errorFactory;
    readonly IPocoFactory<ICrisCallResult> _callResultFactory;
    readonly IDIContainer<AppIdentityDIContainerDefinition.Data> _endpoint;
    readonly CrisExecutionHost _executionHost;
    readonly CrisDirectory _crisDirectory;
    readonly ICrisChannelReceptionHandler? _receptionHandler;
    readonly IEnumerable<ICrisIncomingCommandTransformer> _incomingTransformers;

    public CrisChannelFeatureDriver( TransportFeatureDriver transport,
                                     PocoDirectory pocoDirectory,
                                     IPocoFactory<ICrisResultError> errorFactory,
                                     IPocoFactory<ICrisCallResult> callResultFactory,
                                     IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint,
                                     CrisExecutionHost executionHost,
                                     CrisDirectory crisDirectory,
                                     IEnumerable<ICrisIncomingCommandTransformer> incomingTransformers,
                                     ICrisChannelReceptionHandler? receptionHandler = null )
        : base( transport, isAllowedByDefault: true )
    {
        _crisDirectory = crisDirectory;
        _receptionHandler = receptionHandler;
        _incomingTransformers = incomingTransformers;
        _pocoDirectory = pocoDirectory;
        _errorFactory = errorFactory;
        _callResultFactory = callResultFactory;
        _endpoint = endpoint;
        _executionHost = executionHost;
    }

    protected override bool TryCreateChannel( FeatureLifetimeContext context, TransportFeature transport, out CrisChannelFeature? channel )
    {
        channel = new CrisChannelFeature( transport, _pocoDirectory, _errorFactory, _callResultFactory, _executionHost, _endpoint, _crisDirectory, _receptionHandler, _incomingTransformers );
        return true;
    }
}
