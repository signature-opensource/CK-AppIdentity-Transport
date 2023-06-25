using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Remotes collection is the base of the root <see cref="ApplicationIdentityServiceConfiguration"/>
    /// and <see cref="RemoteGroup"/>.
    /// </summary>
    public class RemoteCollection : ApplicationIdentityObject
    {
        readonly ApplicationIdentityService _appIdentityService;
        IRemote[] _remotes;
        internal readonly PerfectEventSender<IRemote> _remotesChanged;

        internal RemoteCollection( RemoteCollectionConfiguration configuration, ApplicationIdentityService? appIdentityService )
            : base( configuration )
        {
            _appIdentityService = appIdentityService ?? (ApplicationIdentityService)this;
            _remotesChanged = new PerfectEventSender<IRemote>();
            _remotes = configuration.Remotes.Select( CreateFrom ).ToArray();
        }

        IRemote CreateFrom( ApplicationIdentityBaseConfiguration c )
        {
            return c switch
            {
                RemotePartyConfiguration p => new RemoteParty( p, this ),
                RemoteCollectionConfiguration d => new RemoteGroup( d, this ),
                _ => Throw.NotSupportedException<IRemote>()
            };
        }

        /// <summary>
        /// Gets the root application identity.
        /// This is this object if this is the root identity service.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _appIdentityService;

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public RemoteCollectionConfiguration Configuration => Unsafe.As<RemoteCollectionConfiguration>( _configuration );

        /// <summary>
        /// Gets the remotes: <see cref="RemoteGroup"/> or <see cref="RemoteParty"/>.
        /// <para>
        /// This is a snapshot of the remotes, while enumerating <see cref="IRemote.IsDestroyed"/> may be true (or becomes true at any time).
        /// </para>
        /// </summary>
        public IReadOnlyCollection<IRemote> Remotes => _remotes;

        /// <summary>
        /// Gets all the remotes recursively (depth first traversal).
        /// <para>
        /// While enumerating <see cref="IRemote.IsDestroyed"/> may be true (or becomes true at any time).
        /// </para>
        /// </summary>
        public IEnumerable<IRemote> AllRemotes
        {
            get
            {
                foreach( var r in _remotes )
                {
                    yield return r;
                    if( r is RemoteGroup g )
                    {
                        foreach( var rS in g.AllRemotes )
                        {
                            yield return rS;
                        }
                    }
                }
            }
        }

        private protected async Task<IRemote?> AddDynamicRemotePartyAsync( IActivityMonitor monitor,
                                                                           Action<MutableConfigurationSection> configuration,
                                                                           bool allowDomain,
                                                                           AppIdentityAgent agent,
                                                                           string thisDomainName,
                                                                           string thisEnvironmentName )
        {
            Throw.CheckNotNullArgument( configuration );
            var c = CreateDynamicRemoteConfiguration( monitor, configuration, allowDomain, thisDomainName, thisEnvironmentName );
            if( c == null ) return null;
            Debug.Assert( c.Configuration.Key == "Dynamic" );
            var r = CreateFrom( c );
            if( !await agent.InitializeDynamicRemoteAsync( r ) ) return null;
            // The remote is InterlockedAdded to the _remotes only on success (and in the second
            // round of OnSuccess trampoline) by OnSuccessAddRemote below.
            return r;
        }

        internal Task OnSuccessAddRemoteAsync( IActivityMonitor monitor, IRemote r )
        {
            Util.InterlockedAdd( ref _remotes, r );
            if( r is RemoteGroup group )
            {
                // This is to publish "new remotes" events in the root ApplicationIndentityService.RemotesChanged event
                // so that by subscribing to this event, the whole structure change can be tracked.
                return OnSuccessAddRemoteDomainAsync( monitor, group );
            }
            return _remotesChanged.RaiseAsync( monitor, r );
        }

        async Task OnSuccessAddRemoteDomainAsync( IActivityMonitor monitor, RemoteGroup domain )
        {
            // Makes the root appear before its children.
            await _remotesChanged.RaiseAsync( monitor, domain );
            foreach( var sub in domain.Remotes )
            {
                await domain._remotesChanged.SafeRaiseAsync( monitor, sub );
            }
        }

        ApplicationIdentityBaseConfiguration? CreateDynamicRemoteConfiguration( IActivityMonitor monitor,
                                                                                Action<MutableConfigurationSection> configuration,
                                                                                bool allowDomain,
                                                                                string thisDomainName,
                                                                                string thisEnvironmentName )
        {
            // Anchors the new mutable section below this section: lookups apply.
            // 
            // The "Remotes:X" levels are useless. We don't need these because these slots don't carry any
            // information other than the "collection" (array) and the "index" that we totally ignore.
            // 
            var anchor = _configuration.Configuration;
            var remotes = new MutableConfigurationSection( anchor );
            var c = remotes.GetMutableSection( "Dynamic" );
            Debug.Assert( string.IsInterned( c.Key ) == "Dynamic" );
            configuration( c );
            var finalConfig = new ImmutableConfigurationSection( c, anchor );
            var inheritedProps = new InheritedConfigurationProps( _configuration );
            // We obviously have a race condition here on the full name unicity.
            // The fact that no full name conflict offers no guaranty when the new configuration
            // will be added.
            // The fact that a full name conflicts is more interesting... But without more
            // concurrency guaranty.
            // We don't inject any "existing" names here: it is up to the actual add to handle
            // existing remotes.
            var fullNameIndex = new Dictionary<string, ImmutableConfigurationSection>( StringComparer.OrdinalIgnoreCase );
            return ApplicationIdentityServiceConfiguration.CreateRemote( monitor,
                                                                         finalConfig,
                                                                         thisDomainName,
                                                                         thisEnvironmentName,
                                                                         ref inheritedProps,
                                                                         fullNameIndex );
        }

        internal async Task DestroyAsync( IActivityMonitor monitor )
        {
            // Signals the destruction completion of all sub remotes.
            // Clears its whole exposed remotes: when the event is raised, the destroyed
            // remotes must not appear in the Remotes.
            var remotes = Interlocked.Exchange( ref _remotes, Array.Empty<RemoteParty>() );
            foreach( var r in remotes )
            {
                var rI = Unsafe.As<IRemoteInternal>( r );
                Debug.Assert( rI.DestroyTCS != null );
                // This guaranties that an event is raised even for a remote in a destroyed remote.
                // Does this produces too much events (the bridge will relay the events to the root ApplicationIdentityService)?
                // It may be too verbose... but this is logically sound.
                await _remotesChanged.SafeRaiseAsync( monitor, r );
                rI.DestroyTCS.SetResult();
            }
            _remotesChangedBridge.Dispose();
        }


        internal void RemoveDestroyed( IRemote destroyed )
        {
            Util.InterlockedRemove( ref _remotes, destroyed );
        }

    }
}
