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
            : base( remote.Configuration.TenantAppIdentityConfiguration! )            
        {
            _remote = remote;
        }

        internal static bool CheckTenantConfigurationNames( IActivityMonitor monitor,
                                                            string remoteName,
                                                            string remoteEnvironmentName,
                                                            IConfigurationSection configuration )
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

        public ApplicationIdentityService ApplicationIdentityService => _remote.AppIdentityService;

        public string DomainName => _remote.Name;

        public string EnvironmentName => _remote.EnvironmentName;

        public Task FeatureBuildersInitialization => _remote.AppIdentityService.FeatureBuildersInitialization;
    }
}
