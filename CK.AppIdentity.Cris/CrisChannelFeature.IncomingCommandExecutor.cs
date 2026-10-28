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

        public void Execute( Protocol handler, IAbstractCommand command, ActivityMonitor.Token issuerToken, ICrisCallContext? callContext )
        {
            var scopedData = new AppIdentityDIContainerDefinition.Data( _feature.Party ) { _callContext = callContext };
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

        // The reception handler (the identity derived from the caller) configures the ambient services, except for an
        // endpoint-only command: it executes in the channel scope (its handlers may need the IRemoteParty). The current
        // local party of the configured scope is the owner of the remote, as in the channel scope.
        protected override async ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureReceptionAsync( IActivityMonitor monitor,
                                                                                                                          CrisJob job,
                                                                                                                          System.IServiceProvider services )
        {
            var handler = _feature._receptionHandler;
            if( handler == null || job.Command is ICommandEndpointOnly ) return (null, null);
            var data = Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData );
            var (error, hub) = await handler.ConfigureAsync( monitor, services, data._remoteParty, job.Command, data._callContext ).ConfigureAwait( false );
            hub?.Override( new CurrentLocalParty( data._remoteParty.Owner ) );
            return (error, hub);
        }

        // Only the caller-only events travel with the response: the routed ones are dispatched here, where the
        // command executes.
        protected override Task OnImmediateEventAsync( IActivityMonitor monitor, CrisJob job, IEvent e )
        {
            if( e.CrisPocoModel.Kind == CrisPocoKind.CallerOnlyImmediateEvent )
            {
                Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._handler.SendImmediateEvent( monitor, job.IssuerToken.Key, e );
            }
            return Task.CompletedTask;
        }

        protected override Task SetFinalResultAsync( IActivityMonitor monitor, CrisJob job, IExecutedCommand result )
        {
            var handler = Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._handler;
            // The final caller-only events precede the result on the same ordered queue.
            foreach( var e in result.Events )
            {
                if( e.CrisPocoModel.Kind == CrisPocoKind.CallerOnlyEvent ) handler.SendFinalEvent( monitor, job.IssuerToken.Key, e );
            }
            handler.SendExecuted( monitor, job.IssuerToken.Key, result.Result, result.ValidationMessages );
            return Task.CompletedTask;
        }
    }

}
