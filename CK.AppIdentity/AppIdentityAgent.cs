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
    /// Application identity agent.
    /// </summary>
    public sealed class AppIdentityAgent : MicroAgent
    {
        readonly ApplicationIdentityService _service;
        readonly IServiceProvider _serviceProvider;

        internal AppIdentityAgent( ApplicationIdentityService service, IServiceProvider serviceProvider )
            : base( "ApplicationIdentityService Agent." )
        {
            _service = service;
            _serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Gets the service provider of the running application.
        /// </summary>
        public IServiceProvider serviceProvider => _serviceProvider;

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
            using( monitor.OpenInfo( $"Starting ApplicationIdentityService: initializing '{_service._builders.Select( f => f.FeatureName ).Concatenate("', '")}' features." ) )
            {
                var initContext = new FeatureLifetimeContext( monitor, this, _service._builders );
                var result = await initContext.ExecuteSetupAsync();
                if( result == null ) _service._initialization.SetResult();
                else
                {
                    _service._initialization.SetException( result );
                    monitor.CloseGroup( "Failed." );
                }
            }
        }

        protected override ValueTask OnStopAsync( IActivityMonitor monitor )
        {
            var context = new FeatureLifetimeContext( monitor, this, _service._builders );
            return new ValueTask( context.ExecuteTeardownAsync() );
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
            using( monitor.OpenInfo( $"Initializing dynamic Remote '{init.RemoteParty.FullName}' ({_service._builders.Count} feature builders)." ) )
            {
                var context = new FeatureLifetimeContext( monitor, this, _service._builders );
                bool success = await context.ExecuteSetupDynamicRemoteAsync( init.RemoteParty ) == TrampolineResult.TotalSuccess;
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
            using( monitor.OpenInfo( $"Destroying Remote '{destroyed.FullName}'." ) )
            {
                // Enables the feature drivers to cleanup any existing features. 
                var context = new FeatureLifetimeContext( monitor, this, _service._builders );
                await context.ExecuteTeardownDynamicRemoteAsync( destroyed );
                // Removes the destroyed from its host's Remotes array.
                if( destroyed.ApplicationIdentity is DomainApplicationIdentity hosted )
                {
                    // It is useless to cleanup the remote list of a domain that is being destroyed. 
                    if( !hosted.Host.IsDestroyed )
                    {
                        hosted.RemoveDestroyed( destroyed );
                    }
                }
                else destroyed.ApplicationIdentity.ApplicationIdentityService.RemoveDestroyed( destroyed );
                // Signals the destruction completion.
                if( destroyed.DomainApplicationIdentity is DomainApplicationIdentity internalDomain )
                {
                    foreach( var r in internalDomain._remotes )
                    {
                        Debug.Assert( r._destroyTCS != null );
                        r._destroyTCS.SetResult();
                    }
                }
                destroyed._destroyTCS.SetResult();
            }
        }

    }

}
