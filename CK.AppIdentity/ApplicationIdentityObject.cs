using CK.Core;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace CK.AppIdentity
{

    /// <summary>
    /// Base class of all identity objects.
    /// </summary>
    public abstract class ApplicationIdentityObject : IApplicationIdentityObject
    {
        readonly ApplicationIdentityService _appIdentityService;
        private protected readonly ApplicationIdentityObjectConfiguration _configuration;
        object[] _features;

        internal ApplicationIdentityObject( ApplicationIdentityObjectConfiguration configuration, ApplicationIdentityService? appIdentityService )
        {
            Throw.CheckNotNullArgument( configuration );
            _appIdentityService = appIdentityService ?? (ApplicationIdentityService)this;
            _configuration = configuration;
            _features = Array.Empty<object>();
        }

        /// <inheritdoc />
        public ApplicationIdentityService ApplicationIdentityService => _appIdentityService;

        /// <inheritdoc />
        public ApplicationIdentityObjectConfiguration Configuration => _configuration;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public void AddFeature( object feature )
        {
            Util.InterlockedAddUnique( ref _features, feature );
        }

        /// <inheritdoc />
        public T? GetFeature<T>() => _features.OfType<T>().FirstOrDefault();

        /// <inheritdoc />
        public T GetRequiredFeature<T>()
        {
            var feature = _features.OfType<T>().FirstOrDefault();
            if( feature == null ) Throw.InvalidOperationException( $"Unable to find a feature '{typeof( T ).ToCSharpName()}' in '{ToString()}'." );
            return feature;
        }

    }
}
