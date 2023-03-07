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
        readonly string _name;
        readonly Uri? _uri;
        readonly string _domainName;
        readonly string _environmentName;
        private readonly DomainApplicationIdentity? _tenantAppIdentityService;

        internal RemoteParty( IApplicationIdentity appIdentity, RemotePartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
            _name = configuration.Name;
            _uri = configuration.Uri;
            _domainName = configuration.DomainName;
            _environmentName = configuration.EnvironmentName;
            _tenantAppIdentityService = configuration.TenantAppIdentityConfiguration != null
                                        ? new DomainApplicationIdentity( this )
                                        : null;
        }

        IApplicationIdentity IRemoteParty.ApplicationIdentity => _appIdentity;

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/>.
        /// </summary>
        public ApplicationIdentityService AppIdentityService => _appIdentity.ApplicationIdentityService;

        /// <inheritdoc />
        public bool IsDynamic => _configuration == null;

        /// <inheritdoc />
        public string Name => _name;

        /// <inheritdoc />
        public Uri? Uri => _uri;

        /// <inheritdoc />
        public string DomainName => _domainName;

        /// <inheritdoc />
        public string EnvironmentName => _environmentName;

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
