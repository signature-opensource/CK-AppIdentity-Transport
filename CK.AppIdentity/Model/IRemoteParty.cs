using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// A remote party is identified by its <see cref="Name"/> in its <see cref="ApplicationIdentity"/>.
    /// </summary>
    public interface IRemoteParty
    {
        /// <summary>
        /// Gets the application identity.
        /// </summary>
        IApplicationIdentity ApplicationIdentity { get; }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        RemotePartyConfiguration Configuration { get; }

        /// <summary>
        /// Gets the domain name of this party.
        /// </summary>
        string DomainName { get; }

        /// <summary>
        /// Gets the environment name of this party.
        /// </summary>
        string EnvironmentName { get; }

        /// <inheritdoc cref="RemotePartyConfiguration.Name"/>
        string Name { get; }

        /// <summary>
        /// Gets the uri of this party.
        /// This is null if this remote is only a client of this local application.
        /// </summary>
        Uri? Uri { get; }

        /// <summary>
        /// Gets the features associated to this <see cref="IRemoteParty"/>.
        /// </summary>
        IEnumerable<object> Features { get; }


        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        /// <returns>True if the feature has been added, false if the feature already exists.</returns>
        bool AddFeature( object feature );

        /// <summary>
        /// Gets whether this is a dynamic remote party.
        /// </summary>
        bool IsDynamic { get; }
    }
}
