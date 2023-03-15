using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    sealed class RemoteParty : IRootRemoteParty
    {
        object[] _features;
        readonly IApplicationIdentity _appIdentity;
        readonly RemotePartyConfiguration _configuration;
        readonly NormalizedPath _fullName;
        readonly DomainApplicationIdentity? _tenantAppIdentityService;

        internal RemoteParty( IApplicationIdentity appIdentity, RemotePartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
            _tenantAppIdentityService = configuration.DomainConfiguration != null
                                        ? new DomainApplicationIdentity( this )
                                        : null;
            _fullName = LocalParty.BuildFullName( configuration.DomainName, configuration.EnvironmentName, configuration.Name );
        }

        IApplicationIdentity IRemoteParty.ApplicationIdentity => _appIdentity;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/>.
        /// </summary>
        public ApplicationIdentityService AppIdentityService => _appIdentity.ApplicationIdentityService;

        /// <inheritdoc />
        public bool IsDynamic => _configuration == null;

        /// <inheritdoc />
        public string Name => _configuration.Name;

        /// <inheritdoc />
        public NormalizedPath FullName => _fullName;

        /// <inheritdoc />
        public string? Address => _configuration.Address;

        /// <inheritdoc />
        public string DomainName => _configuration.DomainName;

        /// <inheritdoc />
        public string EnvironmentName => _configuration.EnvironmentName;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <inheritdoc />
        public RemotePartyConfiguration Configuration => _configuration;

        public DomainApplicationIdentity? DomainApplicationIdentity => _tenantAppIdentityService;
    }
}
