using System.Collections.Generic;

namespace CK.AppIdentity
{

    /// <summary>
    /// Generalizes <see cref="ApplicationIdentityService"/>, <see cref="ILocalParty"/> and <see cref="IRemoteParty"/>.
    /// </summary>
    public interface IApplicationIdentityObject
    {
        /// <summary>
        /// Gets the configuration object.
        /// <para>
        /// It can be:
        /// <list type="bullet">
        ///  <item>A <see cref="PartyGroupConfiguration"/>.</item>
        ///  <item>A <see cref="RemotePartyConfiguration"/>.</item>
        ///  <item>A <see cref="ApplicationIdentityServiceConfiguration"/>.</item>
        ///  <item>A base <see cref="ApplicationIdentityObjectConfiguration"/> for external remotes.</item>
        /// </list>
        /// The <see cref="ApplicationIdentityObjectConfiguration.Configuration"/> immutable configuration section contain any
        /// possible feature configuration regardless of this object's type or the configuration type.
        /// </para>
        /// </summary>
        ApplicationIdentityObjectConfiguration Configuration { get; }

        /// <summary>
        /// Gets the root application identity service.
        /// </summary>
        ApplicationIdentityService ApplicationIdentityService { get; }

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
        /// Gets the first object feature that is a <typeparamref name="T"/> or null if not found.
        /// </summary>
        /// <typeparam name="T">The feature type.</typeparam>
        /// <returns>The feature or null.</returns>
        T? GetFeature<T>();

        /// <summary>
        /// Gets the first object feature that is a <typeparamref name="T"/> or throws
        /// an <see cref="InvalidOperationException"/>
        /// </summary>
        /// <typeparam name="T">The feature type.</typeparam>
        /// <returns>The feature.</returns>
        T GetRequiredFeature<T>();
    }
}
