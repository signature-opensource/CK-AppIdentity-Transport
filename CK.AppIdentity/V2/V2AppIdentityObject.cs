using CK.Core;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class of all identity objects.
    /// </summary>
    public abstract class V2AppIdentityObject : V2IAppIdentityObject
    {
        private protected readonly V2AppIdentityObjectConfiguration _configuration;
        object[] _features;

        internal V2AppIdentityObject( V2AppIdentityObjectConfiguration configuration )
        {
            _configuration = configuration;
            _features = Array.Empty<object>();
        }

        /// <inheritdoc />
        public string DomainName => _configuration.DomainName;

        /// <inheritdoc />
        public string EnvironmentName => _configuration.EnvironmentName;

        /// <inheritdoc />
        public NormalizedPath FullName => _configuration.FullName;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public void AddFeature( object feature )
        {
            Util.InterlockedAddUnique( ref _features, feature );
        }

        public override string ToString() => _configuration.FullName.Path;
    }
}
