using System.Collections.Generic;

namespace CK.AppIdentity
{
    public interface ILocalParty
    {
        /// <inheritdoc cref="LocalPartyConfiguration.Name"/>
        string Name { get; }

        /// <summary>
        /// Gets the application identity service.
        /// </summary>
        IAppIdentityService AppIdentityService { get; }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        LocalPartyConfiguration Configuration { get; }

        /// <summary>
        /// Gets the features associated to this <see cref="ILocalParty"/>.
        /// </summary>
        IEnumerable<object> Features { get; }

        /// <summary>
        /// Gets the features associated to this <see cref="LocalParty"/>.
        /// </summary>
        bool AddFeature( object feature );
    }
}
