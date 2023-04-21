using CK.Core;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Generalizes the root <see cref="ApplicationIdentityService"/> and <see cref="IDomainApplicationIdentity"/>
    /// when a remote define a domain (see <see cref="IRemoteParty.DomainApplicationIdentity"/>).
    /// </summary>
    public interface IApplicationIdentity
    {
        /// <summary>
        /// Gets the root application identity.
        /// This is this object is this is the root identity service.
        /// </summary>
        ApplicationIdentityService ApplicationIdentityService { get; }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        ApplicationIdentityConfiguration Configuration { get; }

        /// <inheritdoc cref="ApplicationIdentityConfiguration.DomainName"/>
        string DomainName { get; }

        /// <inheritdoc cref="ApplicationIdentityConfiguration.EnvironmentName"/>
        string EnvironmentName { get; }

        /// <summary>
        /// Gets the this local identity.
        /// </summary>
        ILocalParty Local { get; }

        /// <summary>
        /// Gets the remote parties.
        /// </summary>
        IReadOnlyCollection<IRemoteParty> Remotes { get; }

        /// <summary>
        /// Tries to create and initialize a new remote.
        /// This remote will be <see cref="IRemoteParty.IsDynamic"/> and can be destroyed.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to apply.</param>
        /// <returns>The newly created remote party or null if it cannot be created and initialized.</returns>
        Task<IRemoteParty?> AddDynamicRemoteAsync( IAM monitor, Action<MutableConfigurationSection> configuration );
    }
}
