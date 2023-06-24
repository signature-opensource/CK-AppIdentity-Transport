using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// Generalizes <see cref="ApplicationIdentityService"/>, <see cref="ILocalParty"/> and <see cref="IRemoteParty"/>.
    /// </summary>
    public interface V2IAppIdentityObject
    {
        /// <summary>
        /// Gets the domain name.
        /// </summary>
        string DomainName { get; }

        /// <summary>
        /// Gets the environment name.
        /// </summary>
        string EnvironmentName { get; }

        /// <summary>
        /// Gets the full name of this object:
        /// <list type="bullet">
        ///   <item>
        ///   For remote domains (<see cref="V2RemoteDomain"/>), the full name is DomainName/EnvironmentName.</item>
        ///   <item>
        ///   For parties (<see cref="V2LocalParty"/>, <see cref="V2RemoteParty"/> and root and <see cref="V2ApplicationIdentityService"/>),
        ///   the full name is DomainName/PartyName/EnvironmentName.</item>
        /// </list>
        /// </summary>
        NormalizedPath FullName { get; }

        /// <summary>
        /// Gets the features associated to this <see cref="ApplicationIdentityService"/>, <see cref="IRemoteParty"/> or <see cref="ILocalParty"/>.
        /// </summary>
        IEnumerable<object> Features { get; }

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        void AddFeature( object feature );

    }
}
