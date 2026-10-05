using CK.Core;
using CK.Cris;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;


public sealed partial class CrisChannelFeature
{
    /// <summary>
    /// Executes the commands received from the remote and sends back their immediate events and final result.
    /// </summary>
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

        public void Execute( Protocol handler, IAbstractCommand command, ActivityMonitor.Token issuerToken )
        {
            var scopedData = new AppIdentityDIContainerDefinition.Data( _feature.Party );
            var job = new CrisJob( executor: this,
                                   scopedData,
                                   command,
                                   issuerToken,
                                   executingCommand: null,
                                   deferredExecutionInfo: null,
                                   onExecutedCommand: null,
                                   // The command comes from another party: it must always be validated.
                                   incomingValidationCheck: true );
            scopedData._job = job;
            // The answers are sent by the handler that received the command: its messages are
            // queued by the transport controller and survive a reconnection.
            scopedData._handler = handler;
            ExecutionHost.StartJob( job );
        }

        protected override Task OnImmediateEventAsync( IActivityMonitor monitor, CrisJob job, IEvent e )
        {
            Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._handler.SendImmediateEvent( monitor, job.IssuerToken.Key, e );
            return Task.CompletedTask;
        }

        protected override Task SetFinalResultAsync( IActivityMonitor monitor, CrisJob job, IExecutedCommand result )
        {
            Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._handler.SendExecuted( monitor, job.IssuerToken.Key, result.Result, result.ValidationMessages );
            return Task.CompletedTask;
        }
    }

}
