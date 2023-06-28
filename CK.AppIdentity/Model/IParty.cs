using CK.Core;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// All exposed entities of the application identity model are parties.
    /// </summary>
    public interface IParty
    {
        /// <summary>
        /// Gets the configuration object.
        /// <para>
        /// It can be:
        /// <list type="bullet">
        ///  <item>A <see cref="RemotePartyConfiguration"/>.</item>
        ///  <item>A <see cref="ApplicationIdentityServiceConfiguration"/>.</item>
        ///  <item>A <see cref="TenantDomainPartyConfiguration"/>.</item>
        /// </list>
        /// The <see cref="ApplicationIdentityPartyConfiguration.Configuration"/> immutable configuration section contain any
        /// possible feature configuration regardless of this object's type or the configuration type.
        /// </para>
        /// </summary>
        ApplicationIdentityPartyConfiguration Configuration { get; }

        /// <summary>
        /// Gets the root application identity service.
        /// </summary>
        ApplicationIdentityService ApplicationIdentityService { get; }

        /// <summary>
        /// Gets the domain name.
        /// </summary>
        string DomainName { get; }

        /// <summary>
        /// Gets the environment name.
        /// </summary>
        string EnvironmentName { get; }

        /// <summary>
        /// Gets the party name.
        /// </summary>
        string PartyName { get; }

        /// <summary>
        /// Gets the full name of this party.
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

        /// <summary>
        /// Gets the path to the shared directory for this party.
        /// <para>
        /// This directory is shared by all local parties that runs on this computer/file system.
        /// Use <see cref="ILocalParty.PrivateStorePath"/> to obtain the "$Local" directory of a local party.
        /// </para>
        /// </summary>
        NormalizedPath SharedStorePath { get; }

        /// <summary>
        /// Overridden to return the <see cref="FullName"/>.
        /// </summary>
        /// <returns>This full name.</returns>
        string ToString();
    }
}
