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
    /// The optional <see cref="IRemoteParty.DomainApplicationIdentity"/> when a remote defines a domain.
    /// </summary>
    sealed class DomainApplicationIdentity : ApplicationIdentityBase, IDomainApplicationIdentity
    {
        readonly RemoteParty _host;

        internal DomainApplicationIdentity( RemoteParty remote )
            : base( remote.Configuration.DomainConfiguration!, remote )            
        {
            Debug.Assert( remote.ApplicationIdentity is ApplicationIdentityService, "The host is a root." );
            _host = remote;
        }

        /// <summary>
        /// Gets the root application identity service.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _host.ApplicationIdentity.ApplicationIdentityService;

        /// <summary>
        /// Gets the domain name: it is the <see cref="Host"/> domain name.
        /// </summary>
        public string DomainName => _host.Name;

        /// <summary>
        /// Gets the environment name: it is the <see cref="Host"/> environment name.
        /// </summary>
        public string EnvironmentName => _host.EnvironmentName;

        /// <summary>
        /// Gets the remote party that hosts this domain.
        /// </summary>
        public IRemoteParty Host => _host;

        /// <inheritdoc />
        public Task<IRemoteParty?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return AddDynamicRemotePartyAsync( monitor,
                                               configuration,
                                               false,
                                               ((ApplicationIdentityService)_host.ApplicationIdentity).Agent,
                                               _host.Name,
                                               _host.EnvironmentName );
        }


        /// <summary>
        /// Checks that if they exist DomainName and Local:Name are both the remoteName, that the EnvironmentName if it exists is the same as the
        /// remoteEnvironmentName and that no Allow/Disallow properties exist.
        /// </summary>
        /// <param name="monitor"></param>
        /// <param name="remoteName"></param>
        /// <param name="remoteEnvironmentName"></param>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CheckDomainConfigurationNames( IActivityMonitor monitor,
                                                            string remoteName,
                                                            string remoteEnvironmentName,
                                                            ImmutableConfigurationSection configuration )
        {
            bool success = true;
            var configuredDomain = configuration["DomainName"];
            if( configuredDomain != null && configuredDomain != remoteName )
            {
                monitor.Error( $"Invalid '{configuration.Path}:DomainName': it can only be the remote's name '{remoteName}' (not '{configuredDomain}')." );
                success = false;
            }
            var configuredEnvironment = configuration["EnvironmentName"];
            if( configuredEnvironment != null && configuredEnvironment != remoteEnvironmentName )
            {
                monitor.Error( $"Invalid '{configuration.Path}:EnvironmentName': it can only be remote's environment name '{remoteEnvironmentName}' (not '{configuredEnvironment}')." );
                success = false;
            }
            var configuredLocalName = configuration["Local:Name"];
            if( configuredLocalName != null && configuredLocalName != remoteName )
            {
                monitor.Error( $"Invalid '{configuration.Path}:Local:Name': it can only be the remote's name '{remoteName}' (not '{configuredLocalName}')." );
                success = false;
            }
            return success;
        }

        public override string ToString() => $"DomainApplicationIdentity of {_host.FullName.Path}";

    }
}
