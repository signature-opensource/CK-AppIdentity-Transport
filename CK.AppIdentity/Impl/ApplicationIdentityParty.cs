using CK.Core;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class of all identity objects: <see cref="CK.AppIdentity.ApplicationIdentityService"/>,
    /// <see cref="TenantDomainParty"/> and <see cref="RemoteParty"/>.
    /// </summary>
    public abstract class ApplicationIdentityParty : IParty
    {
        readonly ApplicationIdentityService _appIdentityService;
        private protected readonly ApplicationIdentityPartyConfiguration _configuration;
        readonly NormalizedPath _sharedStorePath;
        object[] _features;

        internal ApplicationIdentityParty( ApplicationIdentityPartyConfiguration configuration, ApplicationIdentityService? appIdentityService )
        {
            Throw.CheckNotNullArgument( configuration );
            _appIdentityService = appIdentityService ?? (ApplicationIdentityService)this;
            _configuration = configuration;
            _features = Array.Empty<object>();
            _sharedStorePath = ApplicationIdentityService.ComputeSharedStorePath( configuration.FullName );
            Directory.CreateDirectory( _sharedStorePath );
        }

        /// <inheritdoc />
        public ApplicationIdentityService ApplicationIdentityService => _appIdentityService;

        /// <inheritdoc />
        public ApplicationIdentityPartyConfiguration Configuration => _configuration;

        /// <inheritdoc />
        public string DomainName => Configuration.DomainName;

        /// <inheritdoc />
        public string EnvironmentName => Configuration.EnvironmentName;

        /// <inheritdoc />
        public string PartyName => Configuration.PartyName;

        /// <inheritdoc />
        public NormalizedPath FullName => Configuration.FullName;

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
            if( feature == null ) Throw.InvalidOperationException( $"Unable to find a feature '{typeof( T ).ToCSharpName()}' in '{FullName}'." );
            return feature;
        }

        /// <inheritdoc />
        public NormalizedPath SharedStorePath => _sharedStorePath;

        /// <inheritdoc cref="IParty.ToString"/>
        public override string ToString() => FullName;

    }
}
