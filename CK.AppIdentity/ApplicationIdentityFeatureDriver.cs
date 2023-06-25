using CK.Core;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class for feature builders. Such builders are singleton auto services that can depend on
    /// any other singleton services, including other <see cref="ApplicationIdentityFeatureDriver"/>. 
    /// </summary>
    [CKTypeDefiner]
    public abstract class ApplicationIdentityFeatureDriver : IApplicationIdentityFeatureDriver
    {
        readonly ApplicationIdentityService _s;
        readonly string _featureName;
        readonly bool _isRootAllowed;

        /// <summary>
        /// Initializes a new <see cref="ApplicationIdentityFeatureDriver"/>.
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
        /// Gets the application identity service.
        /// </summary>
        public ApplicationIdentityService ApplicationIdentityService => _s;

        /// <summary>
        /// Gets whether this feature is allowed or disabled at the root <see cref="ApplicationIdentityService"/>.
        /// Use <see cref="IsAllowedFeature(IRemoteParty)"/> to know whether this feature is eventually enabled for
        /// a remote.
        /// </summary>
        public bool IsRootAllowed => _isRootAllowed;

        /// <summary>
        /// Gets whether this feature is enabled for the given remote, accounting the potential intermediate
        /// Allow/DisallowFeatures configuration of the parent DomainApplicationIdentity's remote.
        /// </summary>
        /// <param name="r">The remote party to test.</param>
        /// <returns>True if this feature is allowed, false otherwise.</returns>
        public bool IsAllowedFeature( IRemote r )
        {
            bool domainLevel = r.IsRooted
                                ? _isRootAllowed
                                : r.ApplicationIdentity.Configuration.IsAllowedFeature( _featureName, _isRootAllowed );
            return r.Configuration.IsAllowedFeature( _featureName, domainLevel );
        }

        /// <summary>
        /// Gets whether this feature is enabled for a local party, accounting the potential intermediate
        /// Allow/DisallowFeatures configuration of the parent DomainApplicationIdentity's remote.
        /// </summary>
        /// <param name="r">The local party to test.</param>
        /// <returns>True if this feature is allowed at the local level, false otherwise.</returns>
        public bool IsAllowedFeature( ILocalParty r )
        {
            bool domainLevel = r.IsRooted
                                ? _isRootAllowed
                                : r.ApplicationIdentity.Configuration.IsAllowedFeature( _featureName, _isRootAllowed );
            return r.Configuration.IsAllowedFeature( _featureName, domainLevel );
        }

        /// <summary>
        /// Gets this feature name.
        /// This is this type name without the "FeatureDriver" suffix.
        /// </summary>
        public string FeatureName => _featureName;

        /// <summary>
        /// Must do whatever is required to register features into <see cref="ApplicationIdentityService.Features"/>
        /// and any <see cref="ILocalParty.Features"/>, <see cref="IRemoteParty.Features"/> and <see cref="IRemoteParty.DomainApplicationIdentity"/>'s features.
        /// <para>
        /// The <see cref="ApplicationIdentityService"/> property is available as well as helpers to know if this feature is allowed on
        /// a party (see <see cref="IsAllowedFeature(ILocalParty)"/> and <see cref="IsAllowedFeature(IRemoteParty)"/>).
        /// </para>
        /// <para>
        /// This is called in the same order as this driver has been instantiated: any dependent feature drivers have been initialized.
        /// </para>
        /// </summary>
        /// <param name="context">The lifetime context.</param>
        /// <returns>True on success, false on non recoverable error (errors must be logged).</returns>
        internal protected abstract Task<bool> SetupAsync( FeatureLifetimeContext context );

        /// <summary>
        /// Must do whatever is required to register features into <see cref="ApplicationIdentityObject.Features"/> for the remote and any subordinated remotes
        /// if the remote is a <see cref="RemoteDomain"/>.
        /// <para>
        /// This is called in the same order as this driver has been instantiated: any dependent feature drivers have been initialized.
        /// </para>
        /// </summary>
        /// <param name="context">The lifetime context.</param>
        /// <param name="remote">The dynamic remote party to initialize.</param>
        /// <returns>True on success, false on non recoverable error (errors must be logged).</returns>
        internal protected abstract Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IRemote remote );

        /// <summary>
        /// Called when a dynamic party is destroyed.
        /// <para>
        /// This is called in reverse order (from most dependent feature drivers to basic ones).
        /// </para>
        /// </summary>
        /// <param name="context">The lifetime context.</param>
        /// <param name="remote">The dynamic remote party to cleanup.</param>
        /// <returns>The awaitable.</returns>
        internal protected abstract Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IRemote remote );

        /// <summary>
        /// Called by a stopping agent. Must get rid of any acquired resources at any level.
        /// <para>
        /// This is called in reverse order (from most dependent feature drivers to basic ones).
        /// </para>
        /// </summary>
        /// <param name="context">The lifetime context.</param>
        /// <returns>The awaitable.</returns>
        internal protected abstract Task TeardownAsync( FeatureLifetimeContext context );
    }
}
