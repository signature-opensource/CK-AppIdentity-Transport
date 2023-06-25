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
    public abstract class ApplicationIdentityObject : IApplicationIdentityObject
    {
        private protected readonly ApplicationIdentityBaseConfiguration _configuration;
        object[] _features;

        internal ApplicationIdentityObject( ApplicationIdentityBaseConfiguration configuration )
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
