using CK.Core;
using CK.PerfectEvent;
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
    public sealed class ApplicationIdentityService : ApplicationIdentityParty, IRemoteOwnerInternal, ISingletonAutoService, IHostedService, IAsyncDisposable
    {
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _initialization;
        readonly NormalizedPath _privateStorePath;
        readonly NormalizedPath _sharedStorePath;
        RemoteOwnerImpl _remotes;

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
            _sharedStorePath = ComputeSharedStorePath( FullName );
            _privateStorePath = _sharedStorePath.AppendPart( "$Local" );
            Directory.CreateDirectory( _privateStorePath );
            _remotes = new RemoteOwnerImpl( this );
            _remotes.Initialize( this, configuration.Remotes );
        }

        internal NormalizedPath ComputeSharedStorePath( NormalizedPath fullName )
        {
            Debug.Assert( fullName.Parts.Count >= 2 && fullName.LastPart[0] == '#' );
            var env = fullName.LastPart;
            var p = fullName.Path;
            return Configuration.StoreRootPath.Combine( $"{env}/{p.AsSpan( 0, p.Length - env.Length - 1 )}" );
        }

        internal AppIdentityAgent Agent => _agent;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityServiceConfiguration"/> object.
        /// </summary>
        public new ApplicationIdentityServiceConfiguration Configuration => Unsafe.As<ApplicationIdentityServiceConfiguration>( _configuration );

        /// <summary>
        /// Gets the path to the "$Local" directory of this party inside the <see cref="SharedStorePath"/>.
        /// </summary>
        public NormalizedPath PrivateStorePath => _privateStorePath;

        /// <summary>
        /// Gets the path to the directory of this party.
        /// </summary>
        public NormalizedPath SharedStorePath => _sharedStorePath;

        /// <inheritdoc />
        public IReadOnlyCollection<IRemote> Remotes => _remotes.Remotes;

        /// <inheritdoc />
        public IEnumerable<IRemote> AllRemotes => _remotes.AllRemotes;

        /// <inheritdoc />
        public PerfectEvent<IRemote> RemotesChanged => _remotes.RemotesChanged.PerfectEvent;

        /// <inheritdoc />
        public Task<IRemote?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return _remotes.AddDynamicRemotePartyAsync( this, monitor, configuration, _agent, Configuration.DomainName, Configuration.EnvironmentName );
        }

        PerfectEventSender<IRemote> IRemoteOwnerInternal.RemotesChanged => _remotes.RemotesChanged;

        void IRemoteOwnerInternal.RemoveDestroyed( IRemote destroyed ) => _remotes.RemoveDestroyed( destroyed );

        void IRemoteOwnerInternal.OnSuccessAddRemoteAsync( IActivityMonitor monitor, IRemote r ) => _remotes.OnSuccessAddRemoteAsync( monitor, r );

        /// <summary>
        /// Gets a task that is completed once all the <see cref="AppIdentityFeatureBuilder"/> have been
        /// initialized. Initialization errors are set on this task if exceptions occurred: awaiting this
        /// task will re-throw the initialization errors.
        /// <para>
        /// Use <see cref="Task.IsCompletedSuccessfully"/> to know if initialization has been successful.
        /// </para>
        /// </summary>
        public Task InitializationTask => _initialization.Task;


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
