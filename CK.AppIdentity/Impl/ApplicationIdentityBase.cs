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

        private protected ApplicationIdentityBase( ApplicationIdentityConfiguration configuration, RemoteParty? domainHost, bool isDynamic )
        {
            Debug.Assert( configuration != null );
            _configuration = configuration;
            _local = new LocalParty( (IApplicationIdentity)this, configuration.Local, domainHost );
            _remotes = configuration.Remotes.Select( c => new RemoteParty( (IApplicationIdentity)this, c, isDynamic ) ).ToArray();
        }

        /// <inheritdoc cref="IApplicationIdentity.Local" />
        public ILocalParty Local => _local;

        /// <inheritdoc cref="IApplicationIdentity.Remotes" />
        public IReadOnlyCollection<IRemoteParty> Remotes => _remotes;

        /// <inheritdoc cref="IApplicationIdentity.Configuration" />
        public ApplicationIdentityConfiguration Configuration => _configuration;

        private protected async Task<bool> AddDynamicRemotePartyAsync( IActivityMonitor monitor,
                                                                       Action<MutableConfigurationSection> configuration,
                                                                       bool allowDomain,
                                                                       AppIdentityAgent agent,
                                                                       string thisDomainName,
                                                                       string thisEnvironmentName )
        {
            Throw.CheckNotNullArgument( configuration );
            var c = CreateDynamicRemoteConfiguration( monitor, configuration, allowDomain, thisDomainName, thisEnvironmentName );
            if( c == null ) return false;
            var r = new RemoteParty( (IApplicationIdentity)this, c, true );
            if( !await agent.InitializeDynamicRemoteAsync( r ) ) return false;
            Util.InterlockedAdd( ref _remotes, r );
            return true;
        }

        RemotePartyConfiguration? CreateDynamicRemoteConfiguration( IActivityMonitor monitor,
                                                                    Action<MutableConfigurationSection> configuration,
                                                                    bool allowDomain,
                                                                    string thisDomainName,
                                                                    string thisEnvironmentName )
        {
            // Creates a "Remotes:0" mutable section. The "Remotes" parent enable the new configuration
            // to be hosted by this ApplicationIdentity configuration: lookups apply.
            var remotes = new MutableConfigurationSection( "Remotes" );
            var c = remotes.GetMutableSection( "0" );
            configuration( c );
            var final = new ImmutableConfigurationSection( c, _configuration.Configuration.GetSection( "Remotes" ) );
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
