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
    /// The optional <see cref="IRootRemoteParty.DomainApplicationIdentity"/>.
    /// </summary>
    public sealed class DomainApplicationIdentity : ApplicationIdentityBase, IApplicationIdentity
    {
        readonly RemoteParty _remote;

        internal DomainApplicationIdentity( RemoteParty remote, bool isDynamic )
            : base( remote.Configuration.DomainConfiguration!, remote, isDynamic )            
        {
            _remote = remote;
        }

        /// <summary>
        /// Gets the root application identity service.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _remote.ApplicationIdentity.ApplicationIdentityService;

        /// <summary>
        /// Gets the domain name that is the <see cref="Host"/> domain name.
        /// </summary>
        public string DomainName => _remote.Name;

        /// <summary>
        /// Gets the environment name that is the <see cref="Host"/> environment name.
        /// </summary>
        public string EnvironmentName => _remote.EnvironmentName;

        /// <summary>
        /// Gets the remote party that hosts this domain.
        /// </summary>
        public IRemoteParty Host => _remote;

        /// <inheritdoc />
        public Task FeatureBuildersInitialization => _remote.ApplicationIdentity.ApplicationIdentityService.FeatureBuildersInitialization;

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
    }
}
