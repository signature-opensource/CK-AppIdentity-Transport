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
    /// Singleton hosted service that is the local party and the root collection of <see cref="IOwnedParty"/>.
    /// </summary>
    public sealed class ApplicationIdentityService : LocalParty, IApplicationIdentityService, ISingletonAutoService, IHostedService, IAsyncDisposable
    {
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _initialization;
        readonly internal PerfectEventSender<IOwnedParty> _allPartyChanged;
        internal TenantDomainParty[] _domains;

        /// <summary>
        /// Initializes a new <see cref="ApplicationIdentityService"/> bound to a required configuration.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        /// <param name="serviceProvider">The application service provider.</param>
        public ApplicationIdentityService( ApplicationIdentityServiceConfiguration configuration, IServiceProvider serviceProvider )
            : base( configuration, configuration.Remotes, false, null )
        {
            Throw.CheckNotNullArgument( serviceProvider );
            _builders = new List<ApplicationIdentityFeatureDriver>();
            _initialization = new TaskCompletionSource();
            _agent = new AppIdentityAgent( this, serviceProvider );
            _allPartyChanged = (PerfectEventSender<IOwnedParty>)_remotesChangedBridge.Target;
            _domains = configuration.TenantDomains.Select( c => new TenantDomainParty( c, false, this ) ).ToArray();
        }

        internal NormalizedPath ComputeSharedStorePath( NormalizedPath fullName )
        {
            Debug.Assert( fullName.Parts.Count >= 2 && fullName.LastPart[0] == '#' );
            var env = fullName.LastPart;
            var p = fullName.Path;
            return Configuration.StoreRootPath.Combine( $"{env}/{p.AsSpan( 0, p.Length - env.Length - 1 )}" );
        }

        internal AppIdentityAgent Agent => _agent;

        /// <inheritdoc />
        public new ApplicationIdentityServiceConfiguration Configuration => Unsafe.As<ApplicationIdentityServiceConfiguration>( _configuration );

        /// <inheritdoc />
        public PerfectEvent<IOwnedParty> AllPartyChanged => _allPartyChanged.PerfectEvent;

        /// <inheritdoc />
        public IReadOnlyCollection<ITenantDomainParty> TenantDomains => _domains;

        /// <inheritdoc />
        public IEnumerable<IRemoteParty> AllRemotes
        {
            get
            {
                foreach( var r in _remotes ) yield return r;
                foreach( var d in _domains )
                {
                    foreach( var r in d.Remotes )
                    {
                        yield return r;
                    }
                }
            }
        }

        /// <inheritdoc />
        public IEnumerable<IOwnedParty> Parties => ((IEnumerable<IOwnedParty>)Remotes).Concat( TenantDomains );

        /// <inheritdoc />
        public IEnumerable<IOwnedParty> AllParties
        {
            get
            {
                foreach( var r in _remotes ) yield return r;
                foreach( var d in _domains )
                {
                    yield return d;
                    foreach( var r in d.Remotes )
                    {
                        yield return r;
                    }
                }
            }
        }

        /// <inheritdoc />
        public Task InitializationTask => _initialization.Task;

        /// <inheritdoc />
        public Task<AddedDynamicParties?> AddPartiesAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return AddDynamicPartiesAsync( monitor, configuration, false, false, this );
        }

        /// <inheritdoc />
        public async Task<ITenantDomainParty?> AddTenantDomainAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return (await AddDynamicPartiesAsync( monitor, configuration, false, true, this ).ConfigureAwait( false ))?.Tenants.Single();
        }

        internal Task OnDestroyedAsync( IActivityMonitor monitor, IOwnedParty owned )
        {
            return owned switch
            {
                RemoteParty p => p.Owner.OnDestroyedRemoteAsync( monitor, p ),
                TenantDomainParty d => OnDestroyedDomainAsync( monitor, d ),
                _ => Throw.NotSupportedException<Task>()
            };
        }

        async Task OnDestroyedDomainAsync( IActivityMonitor monitor, TenantDomainParty d )
        {
            Util.InterlockedRemove( ref _domains, d );
            // This destroys the LocalParty's remotes (including calls to OnShutdownOrDestroyedAsync)
            // and clears the _remotes array.
            await d.OnDestroyedAsync( monitor ).ConfigureAwait( false );
            // We raise the event before the final destruction of the domain and
            // its _destroyTCS signal.
            await _allPartyChanged.RaiseAsync( monitor, d ).ConfigureAwait( false );
            await d.OnShutdownOrDestroyedAsync( monitor, true ).ConfigureAwait( false );
        }

        internal Task OnCreatedAsync( IActivityMonitor monitor, IOwnedParty owned )
        {
            return owned switch
            {
                RemoteParty p => p.Owner.OnCreatedRemoteAsync( monitor, p ),
                TenantDomainParty d => OnCreatedDomainAsync( monitor, d ),
                _ => Throw.NotSupportedException<Task>()
            };
        }

        async Task OnCreatedDomainAsync( IActivityMonitor monitor, TenantDomainParty d )
        {
            Util.InterlockedAdd( ref _domains, d );
            // Makes the domain appear before its remotes.
            await _allPartyChanged.RaiseAsync( monitor, d ).ConfigureAwait( false );
            foreach( var r in d.Remotes )
            {
                // There's little chance that subscribers exist on the new remote
                // but it is cleaner to raise the event through it (the bridge will do its job).
                await d.RemotesChangedSender.RaiseAsync( monitor, r ).ConfigureAwait( false );
            }
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

        /// <summary>
        /// Called by the agent when stopping: this service is being disposed.
        /// </summary>
        /// <param name="monitor">The agent's monitor.</param>
        internal async Task OnShutdownAsync( IActivityMonitor monitor )
        {
            foreach( var r in _remotes )
            {
                await r.OnShutdownOrDestroyedAsync( monitor, false );
            }
            foreach( var d in _domains )
            {
                await d.OnShutdownOrDestroyedAsync( monitor, false );
            }

        }

        public override string ToString() => $"Application: {FullName}";

    }
}
