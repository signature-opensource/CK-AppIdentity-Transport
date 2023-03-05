using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// The local party (this application identity).
    /// </summary>
    public sealed class LocalParty : ILocalParty
    {
        object[] _features;
        readonly RootAppIdentityService _appIdentity;
        readonly LocalPartyConfiguration _configuration;

        internal LocalParty( RootAppIdentityService appIdentity, LocalPartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
        }

        /// <inheritdoc />
        public IAppIdentityService AppIdentityService => _appIdentity;

        /// <inheritdoc />
        public string Name => _configuration.Name;

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
