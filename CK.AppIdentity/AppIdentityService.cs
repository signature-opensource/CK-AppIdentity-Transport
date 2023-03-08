using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// The application identity singleton service.
    /// </summary>
    public sealed class AppIdentityService : ISingletonAutoService, IHostedService 
    {
        object[] _features;
        readonly AppIdentityConfiguration _configuration;
        readonly IServiceProvider _serviceProvider;
        readonly LocalParty _local;
        readonly AppIdentityAgent _agent;
        internal readonly List<AppIdentityFeatureBuilder> _builders;
        internal TaskCompletionSource _featureBuilderInitialization;
        internal RemoteParty[] _remotes;
        Task _agentTask;

        /// <summary>
        /// Initialized a new <see cref="AppIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public AppIdentityService( AppIdentityConfiguration configuration, IServiceProvider serviceProvider )
        {
            _features = Array.Empty<object>();
            _configuration = configuration;
            _serviceProvider = serviceProvider;
            _local = new LocalParty( this, configuration.Local );
            _remotes = configuration.Remotes.Select( r => new RemoteParty( this, r ) ).ToArray();
            _builders = new List<AppIdentityFeatureBuilder>();
            _agent = new AppIdentityAgent( this );
            // If it's not started, it is completed.
            _agentTask = Task.CompletedTask;
            _featureBuilderInitialization = new TaskCompletionSource();
        }

        /// <inheritdoc cref="AppIdentityConfiguration.DomainName"/>
        public string DomainName => _configuration.DomainName;

        /// <inheritdoc cref="AppIdentityConfiguration.EnvironmentName"/>
        public string EnvironmentName => _configuration.EnvironmentName;

        /// <summary>
        /// Gets the this local identity.
        /// </summary>
        public LocalParty Local => _local;

        /// <summary>
        /// Gets the remote parties.
        /// </summary>
        public IReadOnlyCollection<RemoteParty> Remotes => _remotes;

        /// <summary>
        /// Gets the features associated to this <see cref="AppIdentityService"/>.
        /// </summary>
        public IEnumerable<object> Features => _features;

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        /// <returns>True if the feature has been added, false if the feature already exists.</returns>
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <summary>
        /// Gets a task that is completed once all the <see cref="AppIdentityFeatureBuilder"/> have been
        /// initialized. Initialization errors are set on this task if exceptions occurred: awaiting this
        /// task will re-throw the initialization errors.
        /// <para>
        /// Use <see cref="Task.IsCompletedSuccessfully"/> to know if initialization has been successful.
        /// </para>
        /// </summary>
        public Task FeatureBuildersInitialization => _featureBuilderInitialization.Task;

        Task IHostedService.StartAsync( CancellationToken cancellationToken )
        {
            if( !cancellationToken.IsCancellationRequested )
            {
                _agentTask = _agent.StartAsync( _serviceProvider );
            }
            return Task.CompletedTask;
        }

        Task IHostedService.StopAsync( CancellationToken cancellationToken )
        {
            _agent.Stop();
            return _agentTask;
        }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        public AppIdentityConfiguration Configuration => _configuration;
    }
}
