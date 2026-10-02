using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;


public sealed partial class CrisChannelFeature
{
    sealed class IncomingCommandExecutor : ContainerCommandExecutor<AppIdentityDIContainerDefinition.Data>
    {
        readonly CrisChannelFeature _feature;

        public IncomingCommandExecutor( CrisChannelFeature crisChannelFeature,
                                        CrisExecutionHost executionHost,
                                        IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint )
            : base( executionHost, endpoint )
        {
            _feature = crisChannelFeature;
        }

        public void Execute( IAbstractCommand command, ActivityMonitor.Token issuerToken, string? authenticationToken )
        {
            var scopedData = new AppIdentityDIContainerDefinition.Data( _feature.Party );
            var job = new CrisJob( executor: this,
                                   scopedData,
                                   command,
                                   issuerToken,
                                   executingCommand: null,
                                   deferredExecutionInfo: null,
                                   onExecutedCommand: null,
                                   incomingValidationCheck: null );
            scopedData._job = job;
            ExecutionHost.StartJob( job );
        }

    }

}
