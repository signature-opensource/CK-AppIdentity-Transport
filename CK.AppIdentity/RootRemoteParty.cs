using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// Remote party can be <see cref="IsDynamic"/>.
    /// </summary>
    public sealed class RootRemoteParty : IRemoteParty
    {
        object[] _features;
        readonly RootAppIdentityService _appIdentity;
        readonly RemotePartyConfiguration _configuration;
        readonly string _name;
        readonly Uri? _uri;
        readonly string _domainName;
        readonly string _environmentName;

        internal RootRemoteParty( RootAppIdentityService appIdentity, RemotePartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
            _name = configuration.Name;
            _uri = configuration.Uri;
            _domainName = configuration.DomainName;
            _environmentName = configuration.EnvironmentName;
        }

        IAppIdentityService IRemoteParty.AppIdentityService => _appIdentity;

        /// <summary>
        /// Gets the <see cref="RootAppIdentityService"/>.
        /// </summary>
        public RootAppIdentityService AppIdentityService => _appIdentity;

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

    }
}
