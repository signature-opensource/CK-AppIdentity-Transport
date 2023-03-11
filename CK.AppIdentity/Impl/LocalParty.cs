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

        internal LocalParty( IApplicationIdentity appIdentity, LocalPartyConfiguration configuration, RemoteParty? domainHost )
        {
            _fullName = domainHost != null
                        ? BuildFullName( domainHost.DomainName, domainHost.EnvironmentName, configuration.Name )
                        : BuildFullName( appIdentity.DomainName, appIdentity.EnvironmentName, configuration.Name );
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
        }

        internal static NormalizedPath BuildFullName( string domainName, string environmentName, string name )
        {
            Debug.Assert( CoreApplicationIdentity.IsValidDomainName( domainName ) );
            Debug.Assert( CoreApplicationIdentity.IsValidIdentifier( environmentName ) );
            Debug.Assert( CoreApplicationIdentity.IsValidIdentifier( name ) );
            int idxFirst = domainName.IndexOf( "/" );
            if( idxFirst > 0 )
            {
                return $"{domainName.AsSpan( 0, idxFirst )}/{environmentName}{domainName.AsSpan( idxFirst )}/{name}";
            }
            return $"{domainName}/{environmentName}/{name}";
        }

        /// <inheritdoc />
        public IApplicationIdentity ApplicationIdentity => _appIdentity;

        /// <inheritdoc />
        public string Name => _configuration.Name;

        /// <inheritdoc />
        public NormalizedPath FullName => _fullName;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <inheritdoc />
        public LocalPartyConfiguration Configuration => _configuration;

    }
}
