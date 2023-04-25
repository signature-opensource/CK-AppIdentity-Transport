using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class for <see cref="ApplicationIdentityService"/> and <see cref="DomainApplicationIdentity"/>.
    /// </summary>
    public abstract class ApplicationIdentityBase
    {
        internal readonly LocalParty _local;
        readonly ApplicationIdentityConfiguration _configuration;
        internal RemoteParty[] _remotes;
        internal readonly PerfectEventSender<IRemoteParty> _remotesChanged;

        private protected ApplicationIdentityBase( ApplicationIdentityConfiguration configuration, RemoteParty? domainHost )
        {
            Debug.Assert( configuration != null );
            _configuration = configuration;
            _local = new LocalParty( (IApplicationIdentity)this, configuration.Local, domainHost );
            _remotesChanged = new PerfectEventSender<IRemoteParty>();
            _remotes = configuration.Remotes.Select( c => new RemoteParty( (IApplicationIdentity)this, c ) ).ToArray();
        }

        /// <inheritdoc cref="IApplicationIdentity.Local" />
        public ILocalParty Local => _local;

        /// <inheritdoc cref="IApplicationIdentity.Remotes" />
        public IReadOnlyCollection<IRemoteParty> Remotes => _remotes;

        /// <inheritdoc cref="IApplicationIdentity.RemotesChanged" />
        public PerfectEvent<IRemoteParty> RemotesChanged => _remotesChanged.PerfectEvent;

        /// <inheritdoc cref="IApplicationIdentity.Configuration" />
        public ApplicationIdentityConfiguration Configuration => _configuration;

        private protected async Task<IRemoteParty?> AddDynamicRemotePartyAsync( IActivityMonitor monitor,
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
            var r = new RemoteParty( (IApplicationIdentity)this, c );
            if( !await agent.InitializeDynamicRemoteAsync( r ) ) return null;
            // The remote is InterlockedAdded to the _remotes only on success (and in the second
            // round of OnSuccess trampoline) by OnSuccessAddRemote below.
            return r;
        }

        internal Task OnSuccessAddRemoteAsync( IActivityMonitor monitor, RemoteParty r )
        {
            Util.InterlockedAdd( ref _remotes, r );
            if( r.DomainApplicationIdentity != null && r.DomainApplicationIdentity.Remotes.Count > 0 )
            {
                // This is to publish "new remotes" events in the root ApplicationIndentityService.RemotesChanged event
                // so that by subscribing to this event, the whole structure change can be tracked.
                return OnSuccessAddRemoteWithSubRemotesAsync( monitor, (ApplicationIdentityBase)r.DomainApplicationIdentity, r );
            }
            return _remotesChanged.RaiseAsync( monitor, r );
        }

        async Task OnSuccessAddRemoteWithSubRemotesAsync( IActivityMonitor monitor, ApplicationIdentityBase domain, RemoteParty r )
        {
            Debug.Assert( r.DomainApplicationIdentity != null && r.DomainApplicationIdentity.Remotes.Count > 0 );
            // Makes the root appear before its children.
            await _remotesChanged.RaiseAsync( monitor, r );
            foreach( var sub in domain.Remotes )
            {
                await domain._remotesChanged.SafeRaiseAsync( monitor, sub );
            }
        }

        RemotePartyConfiguration? CreateDynamicRemoteConfiguration( IActivityMonitor monitor,
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
            var final = new ImmutableConfigurationSection( c, anchor );
            var inheritedProps = new InheritedConfigurationProps( _configuration );
            return  RemotePartyConfiguration.Create( monitor,
                                                     final,
                                                     thisDomainName,
                                                     thisEnvironmentName,
                                                     allowDomain,
                                                     ref inheritedProps,
                                                     _local.Configuration,
                                                     _configuration.Remotes );
        }

        internal void RemoveDestroyed( RemoteParty remoteParty )
        {
            Util.InterlockedRemove( ref _remotes, remoteParty );
        }

    }
}
