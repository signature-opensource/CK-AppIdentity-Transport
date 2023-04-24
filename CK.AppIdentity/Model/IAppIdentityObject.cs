using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// Generalizes <see cref="ApplicationIdentityService"/>, <see cref="ILocalParty"/> and <see cref="IRemoteParty"/>.
    /// </summary>
    public interface IAppIdentityObject
    {
        /// <summary>
        /// Gets the features associated to this <see cref="ApplicationIdentityService"/>, <see cref="IRemoteParty"/> or <see cref="ILocalParty"/>.
        /// </summary>
        IEnumerable<object> Features { get; }

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        void AddFeature( object feature );

        /// <summary>
        /// Atomically (thread safe) removes a feature if it exists.
        /// Does nothing otherwise.
        /// </summary>
        /// <param name="feature">The feature to remove.</param>
        void RemoveFeature( object feature );
    }
}
