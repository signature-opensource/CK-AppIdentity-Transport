using CK.Core;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

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
        readonly FileStore _sharedStore;
        object[] _features;

        internal ApplicationIdentityParty( ApplicationIdentityPartyConfiguration configuration, ApplicationIdentityService? appIdentityService )
        {
            Throw.CheckNotNullArgument( configuration );
            _appIdentityService = appIdentityService ?? (ApplicationIdentityService)this;
            _configuration = configuration;
            _features = Array.Empty<object>();
            _sharedStore = new FileStore( ApplicationIdentityService.ComputeSharedStorePath( configuration.FullName ) );
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
        public IFileStore SharedFileStore => _sharedStore;

        /// <summary>
        /// Called by the service from the stopping agent when the service is being disposed
        /// or when this party has been destroyed.
        /// </summary>
        /// <param name="monitor">The agent's monitor.</param>
        /// <param name="isDestroyed">This party is being destroyed.</param>
        internal virtual ValueTask OnShutdownOrDestroyedAsync( IActivityMonitor monitor, bool isDestroyed )
        {
            _sharedStore.OnShutdownOrDestroyed( monitor, isDestroyed );
            return ValueTask.CompletedTask;
        }

        /// <inheritdoc cref="IParty.ToString"/>
        public override string ToString() => FullName;

    }
}
