using CK.Core;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
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
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _initialization;

        /// <summary>
        /// Initialized a new <see cref="ApplicationIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public ApplicationIdentityService( ApplicationIdentityConfiguration configuration, IServiceProvider serviceProvider )
            : base( configuration, null )
        {
            _features = Array.Empty<object>();
            _builders = new List<ApplicationIdentityFeatureDriver>();
            _initialization = new TaskCompletionSource();
            _agent = new AppIdentityAgent( this, serviceProvider );
        }

        internal AppIdentityAgent Agent => _agent;

        ApplicationIdentityService IApplicationIdentity.ApplicationIdentityService => this;

        /// <inheritdoc cref="ApplicationIdentityConfiguration.DomainName"/>
        public string DomainName => Configuration.DomainName;

        /// <inheritdoc cref="ApplicationIdentityConfiguration.EnvironmentName"/>
        public string EnvironmentName => Configuration.EnvironmentName;

        /// <summary>
        /// Gets a task that is completed once all the <see cref="AppIdentityFeatureBuilder"/> have been
        /// initialized. Initialization errors are set on this task if exceptions occurred: awaiting this
        /// task will re-throw the initialization errors.
        /// <para>
        /// Use <see cref="Task.IsCompletedSuccessfully"/> to know if initialization has been successful.
        /// </para>
        /// </summary>
        public Task InitializationTask => _initialization.Task;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public void AddFeature( object feature )
        {
            Util.InterlockedAddUnique( ref _features, feature );
        }

        /// <inheritdoc />
        public Task<IRemoteParty?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return AddDynamicRemotePartyAsync( monitor, configuration, true, _agent, Configuration.DomainName, Configuration.EnvironmentName );
        }


        Task IHostedService.StartAsync( CancellationToken cancellationToken )
        {
            if( !cancellationToken.IsCancellationRequested )
            {
                // Let the feature initialization be done in the background, in parallel
                // with other hosted services.
                _agent.Start();
            }
            return Task.CompletedTask;
        }

        Task IHostedService.StopAsync( CancellationToken cancellationToken )
        {
            _agent.SendStop();
            return _agent.RunningTask;
        }

        /// <summary>
        /// Disposes this application identity service: this stops the micro agent.
        /// </summary>
        /// <returns>The awaitable.</returns>
        public ValueTask DisposeAsync()
        {
            _agent.SendStop();
            return new ValueTask( _agent.RunningTask );
        }

        public override string ToString() => $"Application: {_local.FullName}";

    }
}
