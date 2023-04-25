using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    /// <summary>
    /// Application identity micro agent.
    /// </summary>
    public sealed class AppIdentityAgent : MicroAgent
    {
        readonly ApplicationIdentityService _service;
        readonly IServiceProvider _serviceProvider;

        internal AppIdentityAgent( ApplicationIdentityService service, IServiceProvider serviceProvider )
            : base( $"ApplicationIdentityService Agent for {service}" )
        {
            _service = service;
            _serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Gets the service provider of the running application.
        /// </summary>
        public IServiceProvider ServiceProvider => _serviceProvider;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/>.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _service;

        internal void Start() => Throw.CheckState( TryStart() == RunningStatus.Running );

        protected override bool OnTryStart( IActivityMonitor monitor )
        {
            // This ensures that all feature providers have been instantiated.
            // We now use the builders that have been registered in the service: they
            // are necessarily topologically ordered by their dependencies so the calls
            // to InitializeAsync follows the ordering.
            int count = _serviceProvider.GetServices<IApplicationIdentityFeatureDriver>().Count();
            if( count != _service._builders.Count )
            {
                var missing = _serviceProvider.GetServices<IApplicationIdentityFeatureDriver>().Except( _service._builders ).Select( b => b.GetType() );
                monitor.Error( $"Found {count} AppIdentityFeatureBuilder but only {_service._builders.Count} have registered themselves." +
                               $" Missing registration for: {missing.Select( t => t.ToCSharpName() ).Concatenate()}." );
                return false;
            }
            return true;
        }

        protected override async ValueTask OnStartAsync( IActivityMonitor monitor )
        {
            using( monitor.OpenInfo( $"Starting {ToString()}: initializing '{_service._builders.Select( f => f.FeatureName ).Concatenate("', '")}' features." ) )
            {
                var initContext = new FeatureLifetimeContext( monitor, this, _service._builders );
                Exception? error = await initContext.ExecuteSetupAsync();
                if( error == null ) _service._initialization.SetResult();
                else
                {
                    _service._initialization.SetException( error );
                    monitor.CloseGroup( "Failed." );
                }
            }
        }

        protected override async ValueTask OnStopAsync( IActivityMonitor monitor )
        {
            var context = new FeatureLifetimeContext( monitor, this, _service._builders );
            await context.ExecuteTeardownAsync().ConfigureAwait( false );
        }

        record class InitializeDynamicRemoteJob( RemoteParty RemoteParty, TaskCompletionSource<bool> Result );

        internal void OnDestroy( RemoteParty remoteParty ) => PushTypedJob( remoteParty );

        internal Task<bool> InitializeDynamicRemoteAsync( RemoteParty r )
        {
            var cts = new TaskCompletionSource<bool>();
            PushTypedJob( new InitializeDynamicRemoteJob( r, cts ) );
            return cts.Task;
        }

        protected override ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            switch( job )
            {
                case RemoteParty destroyed: return HandleDestroyAsync( monitor, destroyed );
                case InitializeDynamicRemoteJob init:
                    if( Status == RunningStatus.Running )
                    {
                        return HandleDynamicRemoteAsync( monitor, init );
                    }
                    else
                    {
                        init.Result.SetResult( false );
                    }
                    break;
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleDynamicRemoteAsync( IActivityMonitor monitor, InitializeDynamicRemoteJob init )
        {
            var r = init.RemoteParty;
            using( monitor.OpenInfo( $"Initializing dynamic Remote '{r.FullName}' ({_service._builders.Count} feature builders)." ) )
            {
                var context = new FeatureLifetimeContext( monitor, this, _service._builders );
                // The new configured remote is published on the second round of the OnSuccess trampoline.
                context.Trampoline.OnSuccess( () =>
                {
                    context.Trampoline.OnSuccess( () => ((ApplicationIdentityBase)r.ApplicationIdentity).OnSuccessAddRemoteAsync( context.Monitor, r ) );
                } );
                bool success = await context.ExecuteSetupDynamicRemoteAsync( r ) == TrampolineResult.TotalSuccess;
                if( !success )
                {
                    monitor.CloseGroup( "Failed." );
                }
                init.Result.SetResult( success );
            }
        }

        async ValueTask HandleDestroyAsync( IActivityMonitor monitor, RemoteParty destroyed )
        {
            Debug.Assert( destroyed._destroyTCS != null );
            var domainDefinition = destroyed.DomainApplicationIdentity as DomainApplicationIdentity;
            using( monitor.OpenInfo( $"Destroying Remote '{destroyed.FullName}'{(domainDefinition != null ? $" (domain with {domainDefinition.Remotes.Count} remotes)": "")}." ) )
            {
                // Enables the feature drivers to tear down any existing features, including the
                // subordinates remotes ones if this remote defines a domain.
                var context = new FeatureLifetimeContext( monitor, this, _service._builders );
                await context.ExecuteTeardownDynamicRemoteAsync( destroyed );

                // Removes the destroyed from its host's Remotes array.
                var host = ((ApplicationIdentityBase)destroyed.ApplicationIdentity);
                host.RemoveDestroyed( destroyed );

                // Should we raise the RemotesChanged event after the Destroy task completion?
                // It seems safer to raise the RemotesChanged after the task completion but the
                // event handling is part of the destroy activity: we raise the destroy events
                // before signaling the end.

                // If we are on a domain definition, destroys it: it will
                // clear its Remotes array, raise the destroy event and complete the destroy tasks
                // for each of the remote and eventually dispose its event bridge. 
                if( domainDefinition != null ) await domainDefinition.DestroyAsync( monitor );

                // Eventually signal the remote's destroy completion and raises the event.
                await host._remotesChanged.SafeRaiseAsync( monitor, destroyed );
                destroyed._destroyTCS.SetResult();
            }
        }

    }

}
