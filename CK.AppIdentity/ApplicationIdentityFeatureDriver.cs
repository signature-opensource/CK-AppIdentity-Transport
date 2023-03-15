using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class for feature builders. Such builders are singleton auto services that can depend on
    /// any other singleton services, including other <see cref="ApplicationIdentityFeatureDriver"/>. When
    /// <see cref="InitializeAsync(IActivityMonitor, AppIdentityAgent)"/> is called, dependent builders have
    /// already been initialized.
    /// </summary>
    [CKTypeDefiner]
    public abstract class ApplicationIdentityFeatureDriver : ISingletonAutoService
    {
        readonly ApplicationIdentityService _s;
        readonly string _featureName;
        readonly bool _isRootAllowed;

        /// <summary>
        /// Initializes a new <see cref="ApplicationIdentityService"/>.
        /// </summary>
        /// <param name="s">The application identity service.</param>
        /// <param name="isAllowedByDefault">Whether the feature is opt-in or opt-out.</param>
        protected ApplicationIdentityFeatureDriver( ApplicationIdentityService s, bool isAllowedByDefault )
        {
            Debug.Assert( "FeatureDriver".Length == 13 );
            var name = GetType().Name;
            if( name.EndsWith( "FeatureDriver_CK" ) ) name = name.Substring( 0, name.Length - 16 );
            else if( name.EndsWith( "FeatureDriver" ) ) name = name.Substring( 0, name.Length - 13 );
            else
            {
                Throw.InvalidOperationException( $"Invalid type name '{name}': a feature driver type name MUST be suffixed with 'FeatureDriver'." );
            }
            _featureName = name;
            // Adding the builder to the list here captures the topological
            // dependency order of the feature builders.
            s._builders.Add( this );
            _s = s;
            _isRootAllowed = s.Configuration.IsAllowedFeature( name, isAllowedByDefault );
        }

        /// <summary>
        /// Gets whether this feature is allowed or disabled at the root <see cref="ApplicationIdentityService"/>.
        /// </summary>
        public bool IsRootAllowed => _isRootAllowed;

        /// <summary>
        /// Gets the application identity service.
        /// </summary>
        protected ApplicationIdentityService ApplicationIdentity => _s;

        /// <summary>
        /// Gets this feature name.
        /// This is this type name without the "FeatureDriver" suffix.
        /// </summary>
        public string FeatureName => _featureName;

        /// <summary>
        /// Must do whatever is required to register features into <see cref="ApplicationIdentityService.Features"/>
        /// and any <see cref="ILocalParty.Features"/>, <see cref="IRemoteParty.Features"/> and <see cref="IRootRemoteParty.DomainApplicationIdentity"/>'s features.
        /// </summary>
        /// <param name="monitor">The monitor to use for this method. Must not be kept.</param>
        /// <param name="appIdentityAgent">The long lived agent that can be used any time.</param>
        /// <returns>True on success, false on non recoverable error.</returns>
        internal protected abstract Task<bool> InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent );
    }
}
