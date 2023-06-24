using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// The local party (this application identity).
    /// </summary>
    sealed class LocalParty : ILocalParty
    {
        object[] _features;
        readonly NormalizedPath _fullName;
        readonly IApplicationIdentity _appIdentity;
        readonly LocalPartyConfiguration _configuration;
        internal bool _isDestroyed;

        internal LocalParty( IApplicationIdentity appIdentity, LocalPartyConfiguration configuration, RemoteParty? domainHost )
        {
            _fullName = domainHost != null
                        ? BuildFullName( domainHost.DomainName, configuration.Name, domainHost.EnvironmentName )
                        : BuildFullName( appIdentity.DomainName, configuration.Name, appIdentity.EnvironmentName );
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
        }

        internal static NormalizedPath BuildFullName( string domainName, string name, string environmentName )
        {
            Debug.Assert( CoreApplicationIdentity.IsValidDomainName( domainName ) );
            Debug.Assert( CoreApplicationIdentity.IsValidPartyName( name ) && name[0] != '$' );
            Debug.Assert( CoreApplicationIdentity.IsValidEnvironmentName( environmentName ) );
            return $"{domainName}/${name}/{environmentName}";
        }

        /// <inheritdoc />
        public IApplicationIdentity ApplicationIdentity => _appIdentity;

        /// <inheritdoc />
        public string Name => _configuration.Name;

        /// <inheritdoc />
        public NormalizedPath FullName => _fullName;

        /// <inheritdoc />
        public bool IsRooted => _appIdentity is ApplicationIdentityService;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public void AddFeature( object feature )
        {
            Util.InterlockedAddUnique( ref _features, feature );
        }

        /// <inheritdoc />
        public LocalPartyConfiguration Configuration => _configuration;

        /// <inheritdoc />
        public bool IsDestroyed => _isDestroyed;

        public override string ToString() => _fullName.Path;
    }
}
