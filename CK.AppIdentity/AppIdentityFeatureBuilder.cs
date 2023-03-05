using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Base class for feature builders. Such builders are singleton auto services that can depend on
    /// any other singleton services, including other <see cref="AppIdentityFeatureBuilder"/>. When
    /// <see cref="InitializeAsync(IActivityMonitor, AppIdentityAgent)"/> is called, dependent builders have
    /// already been initialized.
    /// </summary>
    [CKTypeDefiner]
    public abstract class AppIdentityFeatureBuilder : ISingletonAutoService
    {
        /// <summary>
        /// Initializes a new <see cref="RootAppIdentityService"/>.
        /// </summary>
        /// <param name="s">The application identity service.</param>
        protected AppIdentityFeatureBuilder( RootAppIdentityService s )
        {
            // Adding the builder to the list here captures the topological
            // dependency order of the feature builders.
            s._builders.Add( this );
        }

        /// <summary>
        /// Must do whatever is required to register features into <see cref="RootAppIdentityService.Features"/>,
        /// <see cref="LocalPartyConfiguration.Features"/> and/or <see cref="RootRemoteParty.Features"/>.
        /// </summary>
        /// <param name="monitor">The monitor to use for this method. Must not be kept.</param>
        /// <param name="appIdentityAgent">The long lived agent that can be used any time.</param>
        /// <returns>The awaitable.</returns>
        internal protected abstract Task InitializeAsync( IActivityMonitor monitor, AppIdentityAgent appIdentityAgent );
    }
}
