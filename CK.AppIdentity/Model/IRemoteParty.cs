using System;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    /// <summary>
    /// A remote party is identified by its <see cref="Name"/> in its <see cref="ApplicationIdentity"/> and
    /// may define a <see cref="DomainApplicationIdentity"/> with its subordinated remotes.
    /// </summary>
    public interface IRemoteParty : IParty
    {
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
        /// Gets the address of this party.
        /// This is null if this remote can only be a client of this local application
        /// (i.e. the remote is not a server and we must be a server for it).
        /// </summary>
        string? Address { get; }

        /// <summary>
        /// Gets the <see cref="IDomainApplicationIdentity"/> if this remote defines a domain.
        /// </summary>
        IDomainApplicationIdentity? DomainApplicationIdentity { get; }

        /// <summary>
        /// Gets whether this is a dynamic remote party.
        /// </summary>
        bool IsDynamic { get; }

        /// <summary>
        /// Initiates the destruction of this remote party. <see cref="IsDynamic"/> must be true
        /// otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </summary>
        /// <returns>True if this call destroyed this party, false it is already destroyed.</returns>
        bool SetDestroyed();

        /// <summary>
        /// Destroys this remote. Even if <see cref="SetDestroyed"/> has been called, awaiting this
        /// waits for this remote to be actually destroyed: this can always be awaited.
        /// <para>
        /// <see cref="IsDynamic"/> must be true otherwise an <see cref="InvalidOperationException"/> is thrown.
        /// </para>
        /// </summary>
        /// <returns>The awaitable.</returns>
        Task DestroyAsync();
    }
}
