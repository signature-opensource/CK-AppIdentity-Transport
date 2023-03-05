using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class TenantAppIdentityService : IAppIdentityService
    {
        readonly RootRemoteParty _remote;
        readonly LocalParty _local;
        object[] _features;

        TenantAppIdentityService( RootRemoteParty remote, LocalParty local )
        {
            Debug.Assert( _remote.Configuration.TenantAppIdentityConfiguration != null );
            _features = Array.Empty<object>();
            _remote = remote;
            _local = local;
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
                monitor.Error( $"A configured DomainName is '{configuredDomain}'. If such configuration exists, it can only be the remote's name '{remoteName}'." );
                success = false;
            }
            var configuredEnvironment = configuration["EnvironmentName"];
            if( configuredEnvironment != null && configuredEnvironment != remoteEnvironmentName )
            {
                monitor.Error( $"A configured EnvironmentName is '{configuredEnvironment}'. If such configuration exists, it can only be the remote's environment name '{remoteEnvironmentName}'." );
                success = false;
            }
            var configuredLocalName = configuration["Local:Name"];
            if( configuredLocalName != null && configuredLocalName != remoteName )
            {
                monitor.Error( $"A configured Local:Name is '{configuredLocalName}'. If such configuration exists, it can only be the remote's name '{remoteName}'." );
                success = false;
            }
            return success;
        }

        public RootAppIdentityService RootAppIdentityService => _remote.AppIdentityService;

        public string DomainName => _remote.Name;

        public string EnvironmentName => _remote.EnvironmentName;

        public AppIdentityConfiguration Configuration => _remote.Configuration.TenantAppIdentityConfiguration;

        public LocalParty Local => _local;

        public IReadOnlyCollection<IRemoteParty> Remotes => throw new NotImplementedException();

        public Task FeatureBuildersInitialization => _remote.AppIdentityService.FeatureBuildersInitialization;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }
    }
}
