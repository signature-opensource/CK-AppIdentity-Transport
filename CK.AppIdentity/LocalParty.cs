using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// The local party (this application identity).
    /// </summary>
    public sealed class LocalParty
    {
        object[] _features;
        readonly AppIdentityService _appIdentity;
        readonly LocalPartyConfiguration _configuration;

        internal LocalParty( AppIdentityService appIdentity, LocalPartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
        }

        /// <summary>
        /// Gets the application identity service.
        /// </summary>
        public AppIdentityService AppIdentityService => _appIdentity;

        /// <inheritdoc cref="LocalPartyConfiguration.Name"/>
        public string Name => _configuration.Name;

        /// <summary>
        /// Gets the features associated to this <see cref="LocalParty"/>.
        /// </summary>
        public IEnumerable<object> Features => _features;

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        /// <returns>True if the feature has been added, false if the feature already exists.</returns>
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        public LocalPartyConfiguration Configuration => _configuration;

    }
}
