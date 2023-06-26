using CK.Core;
using CK.PerfectEvent;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Applies to the root <see cref="ApplicationIdentityService"/> and <see cref="PartyGroup"/>.
    /// </summary>
    public interface IRemoteOwner : IApplicationIdentityObject
    {
        /// <summary>
        /// Raised whenever a new remote appears or disappears in this <see cref="Remotes"/> or in
        /// a subordinated <see cref="PartyGroup"/>.
        /// <para>
        /// By subscribing to this event on the root <see cref="ApplicationIdentityService"/>, one can track any structural
        /// change of the whole identity system.
        /// </para>
        /// </summary>
        PerfectEvent<IRemote> RemotesChanged { get; }

        /// <summary>
        /// Gets the direct remotes (<see cref="PartyGroup"/>, <see cref="RemoteParty"/> or <see cref="ExternalParty"/>)
        /// that this group contains.
        /// <para>
        /// This is a snapshot of the remotes, while enumerating <see cref="IRemote.IsDestroyed"/> may be true (or becomes true at any time).
        /// </para>
        /// </summary>
        IReadOnlyCollection<IRemote> Remotes { get; }

        /// <summary>
        /// Gets all the remotes recursively (depth first traversal of any intermediate <see cref="PartyGroup"/>).
        /// <para>
        /// While enumerating <see cref="IRemote.IsDestroyed"/> may be true (or becomes true at any time).
        /// </para>
        /// </summary>
        IEnumerable<IRemote> AllRemotes { get; }

        /// <summary>
        /// Tries to create and initialize a new remote. This remote will be <see cref="IRemote.IsDynamic"/> and can be destroyed.
        /// <list type="bullet">
        ///  <item>
        ///  When a "Parties" key exists, a <see cref="PartyGroup"/> is created.
        ///  </item>
        ///  <item>
        ///  When the Domain name is "External" or "Undefined" a <see cref="ExternalParty"/> is created.
        ///  </item>
        ///  <item>
        ///  When the last part of the DomainName is the same as the PartyName, a <see cref="LocalParty"/> is created: this
        ///  is the domain controller. A domain controller has no address.
        ///  </item>
        ///  <item>
        ///  Otherwise a <see cref="RemoteParty"/> is created.
        ///  </item>
        /// </list>
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to apply.</param>
        /// <returns>The newly created remote or null if it cannot be created and initialized.</returns>
        Task<IRemote?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration );
    }
}
