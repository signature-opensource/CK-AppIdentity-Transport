using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
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

        public void Execute( Protocol handler, IAbstractCommand command, ActivityMonitor.Token issuerToken, ICrisCallEnvelope envelope, IPartyRoutedCommand? route = null, object? resultSealState = null )
        {
            var scopedData = new AppIdentityDIContainerDefinition.Data( _feature.Party ) { _envelope = envelope, _route = route, _resultSealState = resultSealState };
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
        // The inner command of a routed command requires a configured scope: its IRemoteParty would be the last hop.
        // Without reception handler (no authentication package), it executes with the clean ambient services: no
        // identity, the owner of the remote as the current local party.
        protected override async ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureReceptionAsync( IActivityMonitor monitor,
                                                                                                                          CrisJob job,
                                                                                                                          System.IServiceProvider services )
        {
            var handler = _feature._receptionHandler;
            var data = Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData );
            if( handler == null || job.Command is ICommandEndpointOnly )
            {
                if( data._route == null ) return (null, null);
                // Checked by the reception of the routed command: this is a safety net.
                if( job.Command is ICommandEndpointOnly ) return (_feature.CreateError( "A routed command can't be endpoint-only." ), null);
                var clean = services.GetRequiredService<AmbientServiceHub>().CleanClone();
                clean.Override( new CurrentLocalParty( data._remoteParty.Owner ) );
                return (null, clean);
            }
            var caller = new CrisCallerParty( data._remoteParty, data._route );
            var (error, hub) = await handler.ConfigureAsync( monitor, services, caller, job.Command, data._envelope ).ConfigureAwait( false );
            if( error == null && hub == null && data._route != null )
            {
                monitor.Error( $"The reception handler didn't configure '{job.Command.CrisPocoModel.PocoName}' routed from '{caller}': it is refused." );
                return (_feature.CreateError( "A routed command must be configured by the reception handler." ), null);
            }
            hub?.Override( new CurrentLocalParty( data._remoteParty.Owner ) );
            return (error, hub);
        }

        // Only the caller-only events travel with the response: the routed ones are dispatched here, where the
        // command executes.
        protected override Task OnImmediateEventAsync( IActivityMonitor monitor, CrisJob job, IEvent e )
        {
            // The events of a routed command whose result is sealed are not relayed back (the origin ignores them).
            if( e.CrisPocoModel.Kind == CrisPocoKind.CallerOnlyImmediateEvent
                && Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._resultSealState == null )
            {
                Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData )._handler.SendImmediateEvent( monitor, job.IssuerToken.Key, e );
            }
            return Task.CompletedTask;
        }

        protected override Task SetFinalResultAsync( IActivityMonitor monitor, CrisJob job, IExecutedCommand result )
        {
            var data = Unsafe.As<AppIdentityDIContainerDefinition.Data>( job.ScopedData );
            var handler = data._handler;
            if( data._resultSealState != null )
            {
                // The result of a routed command is sealed for its origin: the hops relay what they can't read.
                handler.SendExecuted( monitor, job.IssuerToken.Key, _feature.SealResult( data._resultSealState, result.Result ), default );
                return Task.CompletedTask;
            }
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
