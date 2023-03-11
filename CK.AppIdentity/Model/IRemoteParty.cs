using System;

namespace CK.AppIdentity
{

    /// <summary>
    /// A remote party is identified by its <see cref="Name"/> in its <see cref="ApplicationIdentity"/>.
    /// </summary>
    public interface IRemoteParty : IParty
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
        /// Gets the address of this party.
        /// This is null if this remote can only be a client of this local application
        /// (i.e. the remote is not a server but we must be).
        /// </summary>
        string? Address { get; }

        /// <summary>
        /// Gets whether this is a dynamic remote party.
        /// </summary>
        bool IsDynamic { get; }
    }
}
