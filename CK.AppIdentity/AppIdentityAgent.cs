using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Application identity agent.
    /// </summary>
    public sealed class AppIdentityAgent
    {
        readonly ActivityMonitor _monitor;
        // We use null as the close signal (no need for a cancellation token source).
        readonly Channel<object?> _channel;
        readonly RootAppIdentityService _service;
        readonly IActivityLogger _logger;

        internal AppIdentityAgent( RootAppIdentityService service )
        {
            _monitor = new ActivityMonitor( nameof(RootAppIdentityService), new DateTimeStampProvider() );
            _channel = Channel.CreateUnbounded<object?>( new UnboundedChannelOptions { SingleReader = true } );
            _service = service;
            _logger = new Logger( this );
        }

        /// <summary>
        /// Gets the application identity logger.
        /// </summary>
        public IActivityLogger logger => _logger;


        internal Task StartAsync( IServiceProvider serviceProvider )
        {
            // This ensures that all feature providers have been instantiated.
            // We now use the builders that have been registered in the service: they
            // are necessarily topologically ordered by their dependencies so the calls
            // to InitializeAsync follows the ordering.
            int count = serviceProvider.GetServices<AppIdentityFeatureBuilder>().Count();
            if( count != _service._builders.Count )
            {
                var missing = serviceProvider.GetServices<AppIdentityFeatureBuilder>().Except( _service._builders ).Select( b => b.GetType() );
                Throw.InvalidOperationException( $"Found {count} AppIdentityFeatureBuilder but only {_service._builders.Count} have registered themselves." +
                                                 $" Missing registration for: {missing.Select( t => t.ToCSharpName()).Concatenate()}." );
            }
            return Task.Run( RunAsync );
        }

        internal bool Stop()
        {
            // Writes the null sentinel to the channel and completes the channel.
            return _channel.Writer.TryWrite( null ) && _channel.Writer.TryComplete();
        }

        sealed class Logger : IActivityLogger
        {
            readonly AppIdentityAgent _agent;

            public Logger( AppIdentityAgent agent )
            {
                _agent = agent;
            }

            public CKTrait AutoTags => _agent._monitor.AutoTags;

            public LogLevelFilter ActualFilter => _agent._monitor.ActualFilter.Line;

            public void UnfilteredLog( ref ActivityMonitorLogData data )
            {
                Debug.Assert( _agent._monitor.SafeStampProvider != null, "Using the stamp provider of the monitor." );
                var e = data.AcquireExternalData( _agent._monitor.SafeStampProvider );
                if( !_agent._channel.Writer.TryWrite( e ) )
                {
                    e.Release();
                }
            }
        }

        async Task RunAsync()
        {
            using( _monitor.OpenInfo( $"Initializing {_service._builders.Count} AppIdentityFeatureBuilder." ) )
            {
                List<Exception>? agg = null;
                foreach( var b in _service._builders )
                {
                    try
                    {
                        await b.InitializeAsync( _monitor, this );
                    }
                    catch( Exception ex )
                    {
                        _monitor.Error( $"Error while initializing AppIdentityFeatureBuilder '{b.GetType():C}'.", ex );
                        agg ??= new List<Exception>();
                        agg.Add( ex );
                    }
                }
                if( agg == null ) _service._featureBuilderInitialization.SetResult();
                else
                {
                    _service._featureBuilderInitialization.SetException( agg.Count == 1 ? agg[0] : new AggregateException( agg ) );
                    _monitor.CloseGroup( "Failed." );
                }
            }
            // We pool the channel until the null closing signal.
            object? o;
            while( (o = await _channel.Reader.ReadAsync()) != null )
            {
                switch( o )
                {
                    case ActivityMonitorExternalLogData data:
                        {
                            var d = new ActivityMonitorLogData( data );
                            _monitor.UnfilteredLog( ref d );
                            // If the data has been acquired again by Clients, it will
                            // live longer, but for us, we are done with it.
                            data.Release();
                            break;
                        }
                }
            }
            // Securing the race condition that MAY happen.
            while( _channel.Reader.TryRead( out o ) )
            {
                if( o is ActivityMonitorExternalLogData data ) data.Release();
            }
            _monitor.MonitorEnd();
        }
    }
}
