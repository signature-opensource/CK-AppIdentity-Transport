using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class DomainApplicationIdentity : ApplicationIdentityBase, IApplicationIdentity
    {
        readonly RemoteParty _remote;

        internal DomainApplicationIdentity( RemoteParty remote )
            : base( remote.Configuration.TenantAppIdentityConfiguration!, remote )            
        {
            _remote = remote;
        }

        const string ReasonPhraseForInheritedPropertyInDomain = "This configuration is defined at the Remote level, not in the Domain.";

        /// <summary>
        /// Checks that if they exist DomainName and Local:Name are both the remoteName, that the EnvironmentName if it exists is the same as the
        /// remoteEnvironmentName and that no Allow/Disallow properties exist.
        /// </summary>
        /// <param name="monitor"></param>
        /// <param name="remoteName"></param>
        /// <param name="remoteEnvironmentName"></param>
        /// <param name="configuration"></param>
        /// <returns></returns>
        internal static bool CheckTenantConfigurationNames( IActivityMonitor monitor,
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
            if( ApplicationIdentityConfiguration.ErrorOnProperty( monitor, configuration, "AllowFeatures", ReasonPhraseForInheritedPropertyInDomain ) ) success = false;
            if( ApplicationIdentityConfiguration.ErrorOnProperty( monitor, configuration, "DisallowFeatures", ReasonPhraseForInheritedPropertyInDomain ) ) success = false;
            return success;
        }

        public ApplicationIdentityService ApplicationIdentityService => _remote.AppIdentityService;

        public string DomainName => _remote.Name;

        public string EnvironmentName => _remote.EnvironmentName;

        public Task FeatureBuildersInitialization => _remote.AppIdentityService.FeatureBuildersInitialization;
    }
}
