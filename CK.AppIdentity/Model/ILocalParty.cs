using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// The local party (this application identity).
    /// </summary>
    public interface ILocalParty
    {
        /// <inheritdoc cref="LocalPartyConfiguration.Name"/>
        string Name { get; }

        /// <summary>
        /// Gets the application identity.
        /// </summary>
        IApplicationIdentity ApplicationIdentity { get; }

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
