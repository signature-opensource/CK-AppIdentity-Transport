using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
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
            : base( "ApplicationIdentityService micro agent." )
        {
            _service = service;
            _serviceProvider = serviceProvider;
        }

        internal void Start() => Throw.CheckState( TryStart() == RunningStatus.Running );

        protected override bool OnTryStart( IActivityMonitor monitor )
        {
            // This ensures that all feature providers have been instantiated.
            // We now use the builders that have been registered in the service: they
            // are necessarily topologically ordered by their dependencies so the calls
            // to InitializeAsync follows the ordering.
            int count = _serviceProvider.GetServices<ApplicationIdentityFeatureDriver>().Count();
            if( count != _service._builders.Count )
            {
                var missing = _serviceProvider.GetServices<ApplicationIdentityFeatureDriver>().Except( _service._builders ).Select( b => b.GetType() );
                monitor.Error( $"Found {count} AppIdentityFeatureBuilder but only {_service._builders.Count} have registered themselves." +
                               $" Missing registration for: {missing.Select( t => t.ToCSharpName() ).Concatenate()}." );
                return false;
            }
            return true;
        }

        protected override async ValueTask OnStartAsync( IActivityMonitor monitor )
        {
            using( monitor.OpenInfo( $"Starting ApplicationIdentityService: initializing {_service._builders.Count} AppIdentityFeatureBuilder." ) )
            {
                var initContext = new FeatureInitializatonContext( monitor, this, _service._builders );
                var result = await initContext.ExecuteInitializationAsync();
                if( result == null ) _service._featureBuilderInitialization.SetResult();
                else
                {
                    _service._featureBuilderInitialization.SetException( result );
                    monitor.CloseGroup( "Failed." );
                }
            }
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
                case InitializeDynamicRemoteJob init: return HandleDynamicRemoteAsync( monitor, init );
            }
            return base.ExecuteTypedJobAsync( monitor, job );
        }

        async ValueTask HandleDynamicRemoteAsync( IActivityMonitor monitor, InitializeDynamicRemoteJob init )
        {
            using( monitor.OpenInfo( $"Initializing dynamic Remote '{init.RemoteParty.FullName}' ({_service._builders.Count} feature builders)." ) )
            {
                var initContext = new FeatureInitializatonContext( monitor, this, _service._builders );
                bool success = await initContext.ExecuteDynamicRemoteInitializationAsync( init.RemoteParty ) == TrampolineResult.TotalSuccess;
                if( !success )
                {
                    monitor.CloseGroup( "Failed." );
                }
                init.Result.SetResult( success );
            }
        }

        ValueTask HandleDestroyAsync( IActivityMonitor monitor, RemoteParty destroyed )
        {
            monitor.Info( $"Destroying Remote {destroyed.FullName}." );
            var hosted = destroyed.ApplicationIdentity as DomainApplicationIdentity;
            if( hosted != null )
            {
                // It is useless to cleanup the remote list of a domain that is being destroyed. 
                if( !hosted.Host.IsDestroyed )
                {
                    hosted.RemoveDestroyed( destroyed );
                }
            }
            else destroyed.ApplicationIdentity.ApplicationIdentityService.RemoveDestroyed( destroyed );
            return default;
        }
    }

}
