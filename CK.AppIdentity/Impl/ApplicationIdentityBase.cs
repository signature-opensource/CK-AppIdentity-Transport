using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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

        private protected ApplicationIdentityBase( ApplicationIdentityConfiguration configuration, RemoteParty? domainHost )
        {
            Debug.Assert( configuration != null );
            _configuration = configuration;
            _local = new LocalParty( (IApplicationIdentity)this, configuration.Local, domainHost );
            _remotes = configuration.Remotes.Select( c => new RemoteParty( (IApplicationIdentity)this, c ) ).ToArray();
        }

        /// <inheritdoc cref="IApplicationIdentity.Local" />
        public ILocalParty Local => _local;

        /// <inheritdoc cref="IApplicationIdentity.Remotes" />
        public IReadOnlyCollection<IRemoteParty> Remotes => _remotes;

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
            Util.InterlockedAdd( ref _remotes, r );
            return r;
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
