using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;


public sealed partial class CrisChannelFeature
{
    sealed class IncomingCommandExecutor : EndpointCommandExecutor<AppIdentityEndpointDefinition.Data>
    {
        public IncomingCommandExecutor( CrisExecutionHost executionHost, IEndpointType<AppIdentityEndpointDefinition.Data> endpoint )
            : base( executionHost, endpoint )
        {
        }

        public void Execute( IAbstractCommand command, ActivityMonitor.Token issuerToken, string? authenticationToken )
        {
            var scopedData = new AppIdentityEndpointDefinition.Data( authenticationToken );
            var job = new CrisJob( this, scopedData, command, issuerToken, false, null );
            scopedData._job = job;
            ExecutionHost.StartJob( job );
        }
    }

}
