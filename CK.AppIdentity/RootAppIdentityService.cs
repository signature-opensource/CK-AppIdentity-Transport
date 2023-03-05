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
    public sealed class RootAppIdentityService : ISingletonAutoService, IHostedService, IAppIdentityService
    {
        object[] _features;
        readonly AppIdentityConfiguration _configuration;
        readonly IServiceProvider _serviceProvider;
        readonly LocalParty _local;
        readonly AppIdentityAgent _agent;
        internal readonly List<AppIdentityFeatureBuilder> _builders;
        internal TaskCompletionSource _featureBuilderInitialization;
        internal RootRemoteParty[] _remotes;
        Task _agentTask;

        /// <summary>
        /// Initialized a new <see cref="RootAppIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public RootAppIdentityService( AppIdentityConfiguration configuration, IServiceProvider serviceProvider )
        {
            _features = Array.Empty<object>();
            _configuration = configuration;
            _serviceProvider = serviceProvider;
            _local = new LocalParty( this, configuration.Local );
            _remotes = configuration.Remotes.Select( r => new RootRemoteParty( this, r ) ).ToArray();
            _builders = new List<AppIdentityFeatureBuilder>();
            _agent = new AppIdentityAgent( this );
            // If it's not started, it is completed.
            _agentTask = Task.CompletedTask;
            _featureBuilderInitialization = new TaskCompletionSource();
        }

        RootAppIdentityService IAppIdentityService.RootAppIdentityService => this;

        /// <inheritdoc cref="AppIdentityConfiguration.DomainName"/>
        public string DomainName => _configuration.DomainName;

        /// <inheritdoc cref="AppIdentityConfiguration.EnvironmentName"/>
        public string EnvironmentName => _configuration.EnvironmentName;

        /// <inheritdoc />
        public LocalParty Local => _local;

        IReadOnlyCollection<IRemoteParty> IAppIdentityService.Remotes => _remotes;

        /// <inheritdoc />
        public IReadOnlyCollection<RootRemoteParty> Remotes => _remotes;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <inheritdoc />
        public AppIdentityConfiguration Configuration => _configuration;

        /// <inheritdoc />
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

    }
}
