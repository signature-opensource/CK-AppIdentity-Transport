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
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    /// <summary>
    /// A Remote with Remotes is a domain.
    /// </summary>
    public class ApplicationIdentityDomain : ApplicationIdentityObject
    {
        readonly ApplicationIdentityService _appIdentityService;
        IRemote[] _remotes;
        internal readonly PerfectEventSender<IRemote> _remotesChanged;

        internal ApplicationIdentityDomain( DomainConfiguration configuration, ApplicationIdentityService? appIdentityService )
            : base( configuration )
        {
            _appIdentityService = appIdentityService ?? (ApplicationIdentityService)this;
            _remotesChanged = new PerfectEventSender<IRemote>();
            _remotes = configuration.Remotes.Select( CreateFrom ).ToArray();
        }

        IRemote CreateFrom( AppIdentityObjectConfiguration c )
        {
            return c switch
            {
                RemotePartyConfiguration p => new RemoteParty( p, this ),
                DomainConfiguration d => new RemoteDomain( d, this ),
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
        public DomainConfiguration Configuration => Unsafe.As<DomainConfiguration>( _configuration );

        /// <summary>
        /// Gets the local party. Its <see cref="LocalPartyConfiguration.PartyName"/> is the
        /// domain leaf name.
        /// </summary>
        public LocalParty Local => _local;

        /// <summary>
        /// Gets the remotes: <see cref="RemoteDomain"/> or <see cref="RemoteParty"/> <see cref="V2DomainBase"/>.
        /// </summary>
        public IReadOnlyCollection<IRemote> Remotes => _remotes;

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
            if( r is RemoteDomain domain )
            {
                // This is to publish "new remotes" events in the root ApplicationIndentityService.RemotesChanged event
                // so that by subscribing to this event, the whole structure change can be tracked.
                return OnSuccessAddRemoteDomainAsync( monitor, domain );
            }
            return _remotesChanged.RaiseAsync( monitor, r );
        }

        async Task OnSuccessAddRemoteDomainAsync( IActivityMonitor monitor, RemoteDomain domain )
        {
            // Makes the root appear before its children.
            await _remotesChanged.RaiseAsync( monitor, domain );
            foreach( var sub in domain.Remotes )
            {
                await domain._remotesChanged.SafeRaiseAsync( monitor, sub );
            }
        }

        AppIdentityObjectConfiguration? CreateDynamicRemoteConfiguration( IActivityMonitor monitor,
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
            return ApplicationIdentityServiceConfiguration.CreateRemote( monitor,
                                                                         finalConfig,
                                                                         thisDomainName,
                                                                         thisEnvironmentName,
                                                                         allowDomain,
                                                                         ref inheritedProps,
                                                                         _local.Configuration,
                                                                         Configuration.Remotes );
        }

        internal void RemoveDestroyed( RemoteParty remoteParty )
        {
            Util.InterlockedRemove( ref _remotes, remoteParty );
        }

    }
}
