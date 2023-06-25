using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Singleton hosted service that is the local party and the root collection of <see cref="IRemote"/>.
    /// </summary>
    public sealed class ApplicationIdentityService : RemoteCollection, ISingletonAutoService, IHostedService, IAsyncDisposable
    {
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _initialization;
        readonly NormalizedPath _privateStorePath;
        readonly NormalizedPath _sharedStorePath;

        /// <summary>
        /// Initializes a new <see cref="ApplicationIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        /// <param name="serviceProvider">The application service provider.</param>
        public ApplicationIdentityService( ApplicationIdentityServiceConfiguration configuration, IServiceProvider serviceProvider )
            : base( configuration, null )
        {
            Throw.CheckNotNullArgument( serviceProvider );
            _builders = new List<ApplicationIdentityFeatureDriver>();
            _initialization = new TaskCompletionSource();
            _agent = new AppIdentityAgent( this, serviceProvider );
            _sharedStorePath = configuration.StoreRootPath.Combine( FullName );
            _privateStorePath = _sharedStorePath.AppendPart( "$Local" );
            Directory.CreateDirectory( _privateStorePath );
        }

        internal AppIdentityAgent Agent => _agent;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityServiceConfiguration"/> object.
        /// </summary>
        public new ApplicationIdentityServiceConfiguration Configuration => Unsafe.As<ApplicationIdentityServiceConfiguration>( _configuration );

        /// <summary>
        /// Gets the this application party name.
        /// </summary>
        public string PartyName => Configuration.PartyName;

        /// <summary>
        /// Gets the path to the "$Local" directory of this party inside the <see cref="SharedStorePath"/>.
        /// </summary>
        public NormalizedPath PrivateStorePath => _privateStorePath;

        /// <summary>
        /// Gets the path to the directory of this party.
        /// </summary>
        public NormalizedPath SharedStorePath => _sharedStorePath;

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
        public Task<IRemote?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
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
        public async ValueTask DisposeAsync()
        {
            _agent.SendStop();
            await _agent.RunningTask.ConfigureAwait( false );
        }

        public override string ToString() => $"Application: {FullName}";
    }
}
