using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    /// <summary>
    /// The application identity singleton service. This is the root of the application identity model.
    /// </summary>
    public sealed class ApplicationIdentityService : ApplicationIdentityBase, ISingletonAutoService, IHostedService, IApplicationIdentity, IAppIdentityObject, IAsyncDisposable
    {
        object[] _features;
        readonly IServiceProvider _serviceProvider;
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _featureBuilderInitialization;
        Task _agentTask;

        /// <summary>
        /// Initialized a new <see cref="ApplicationIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public ApplicationIdentityService( ApplicationIdentityConfiguration configuration, IServiceProvider serviceProvider )
            : base( configuration, null )
        {
            _features = Array.Empty<object>();
            _serviceProvider = serviceProvider;
            _builders = new List<ApplicationIdentityFeatureDriver>();
            _agent = new AppIdentityAgent( this );
            // If it's not started, then it is completed.
            _agentTask = Task.CompletedTask;
            _featureBuilderInitialization = new TaskCompletionSource();
        }

        ApplicationIdentityService IApplicationIdentity.ApplicationIdentityService => this;

        /// <inheritdoc cref="ApplicationIdentityConfiguration.DomainName"/>
        public string DomainName => Configuration.DomainName;

        /// <inheritdoc cref="ApplicationIdentityConfiguration.EnvironmentName"/>
        public string EnvironmentName => Configuration.EnvironmentName;

        /// <inheritdoc />
        public new IReadOnlyCollection<IRootRemoteParty> Remotes => _remotes;

        /// <inheritdoc />
        public Task FeatureBuildersInitialization => _featureBuilderInitialization.Task;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

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
        /// Disposes this application identity service: this stops the micro agent.
        /// </summary>
        /// <returns>The awaitable.</returns>
        public ValueTask DisposeAsync()
        {
            _agent.Stop();
            return new ValueTask( _agentTask );
        }
    }
}
