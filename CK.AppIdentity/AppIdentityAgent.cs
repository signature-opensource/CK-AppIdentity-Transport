using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
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
                List<Exception>? agg = null;

                foreach( var b in _service._builders )
                {
                    try
                    {
                        await b.InitializeAsync( monitor, this );
                    }
                    catch( Exception ex )
                    {
                        monitor.Error( $"Error while initializing AppIdentityFeatureBuilder '{b.GetType():C}'.", ex );
                        agg ??= new List<Exception>();
                        agg.Add( ex );
                    }
                }
                if( agg == null ) _service._featureBuilderInitialization.SetResult();
                else
                {
                    _service._featureBuilderInitialization.SetException( agg.Count == 1 ? agg[0] : new AggregateException( agg ) );
                    monitor.CloseGroup( "Failed." );
                }
            }
        }
    }
}
