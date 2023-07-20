using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// A local party is the root <see cref="IApplicationIdentityService"/> or a <see cref="ITenantDomainParty"/>.
    /// It owns remotes (the root service also owns tenant domains).
    /// </summary>
    public interface ILocalParty : IParty
    {
        /// <summary>
        /// Raised whenever a new party appears or disappears in this <see cref="Remotes".
        /// <para>
        /// By subscribing to this event on the root <see cref="ApplicationIdentityService"/>, one can track any structural
        /// change of the whole identity system.
        /// </para>
        /// </summary>
        PerfectEvent<IRemoteParty> RemotesChanged { get; }

        /// <summary>
        /// Gets the remote parties.
        /// <para>
        /// This is a snapshot: while enumerating <see cref="IOwnedParty.IsDestroyed"/> may be true (or becomes true at any time).
        /// </para>
        /// </summary>
        IReadOnlyCollection<IRemoteParty> Remotes { get; }

        /// <summary>
        /// Tries to create and initialize one or more new remotes from a configuration section.
        /// These remotes will be <see cref="IOwnedParty.IsDynamic"/> and can be destroyed.
        /// <para>
        /// No tenant domains must appear in the configuration otherwise an <see cref="ArgumentException"/> is thrown.
        /// </para>
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to process.</param>
        /// <returns>The newly created remotes or null if an error occurred.</returns>
        Task<IReadOnlyCollection<IRemoteParty>?> AddMultipleRemotesAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration );

        /// <summary>
        /// Tries to create and initialize a single remote from a configuration section.
        /// This remote will be <see cref="IOwnedParty.IsDynamic"/> and can be destroyed.
        /// <para>
        /// Only one remote must appear in the configuration otherwise an <see cref="ArgumentException"/> is thrown.
        /// </para>
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to process.</param>
        /// <returns>The newly created remote or null if an error occurred.</returns>
        Task<IRemoteParty?> AddRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration );

        /// <summary>
        /// Gets the private local file store. This is the "-Local" directory inside this <see cref="IParty.SharedFileStore"/>.
        /// </summary>
        IFileStore LocalFileStore { get; }

    }
}
