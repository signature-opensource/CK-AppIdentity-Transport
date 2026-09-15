using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;


public sealed partial class CrisChannelFeature
{
    sealed class IncomingCommandExecutor : ContainerCommandExecutor<AppIdentityEndpointDefinition.Data>
    {
        public IncomingCommandExecutor( CrisExecutionHost executionHost, IDIContainer<AppIdentityEndpointDefinition.Data> endpoint )
            : base( executionHost, endpoint )
        {
        }

        public void Execute( IAbstractCommand command, ActivityMonitor.Token issuerToken, string? authenticationToken )
        {
            var scopedData = new AppIdentityEndpointDefinition.Data( authenticationToken );
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
