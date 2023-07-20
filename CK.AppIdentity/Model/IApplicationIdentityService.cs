using CK.Core;
using System.Threading.Tasks;
using System;
using CK.PerfectEvent;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using System.Runtime.CompilerServices;

namespace CK.AppIdentity
{
    /// <summary>
    /// Root of the identity model. Contains all the identity objects.
    /// </summary>
    public interface IApplicationIdentityService : ILocalParty
    {
        /// <summary>
        /// Gets the <see cref="ApplicationIdentityServiceConfiguration"/> object.
        /// </summary>
        new ApplicationIdentityServiceConfiguration Configuration { get; }

        /// <summary>
        /// Raised whenever a new party appears or disappears in <see cref="AllParties"/>.
        /// <para>
        /// By subscribing to this event one can track any structural
        /// change of the whole identity system.
        /// </para>
        /// </summary>
        PerfectEvent<IOwnedParty> AllPartyChanged { get; }

        /// <summary>
        /// Gets the tenant domains that this application hosts.
        /// <para>
        /// This is a snapshot of the parties: while enumerating <see cref="IOwnedParty.IsDestroyed"/> may be
        /// true (or becomes true at any time).
        /// </para>
        /// </summary>
        IReadOnlyCollection<ITenantDomainParty> TenantDomains { get; }

        /// <summary>
        /// Gets a concatenation of the <see cref="LocalParty.Remotes"/> directly owned by this application
        /// and the <see cref="TenantDomains"/>.
        /// <para>
        /// This is a snapshot of the parties: while enumerating <see cref="IOwnedParty.IsDestroyed"/> may be
        /// true (or becomes true at any time).
        /// </para>
        /// </summary>
        IEnumerable<IOwnedParty> Parties { get; }

        /// <summary>
        /// Gets the <see cref="LocalParty.Remotes"/> directly owned by this application, and all remotes of the <see cref="TenantDomains"/>
        /// recursively (depth-first traversal).
        /// <para>
        /// This is a snapshot of the parties: while enumerating <see cref="IOwnedParty.IsDestroyed"/> may be
        /// true (or becomes true at any time).
        /// </para>
        /// </summary>
        IEnumerable<IRemoteParty> AllRemotes { get; }

        /// <summary>
        /// Gets the complete set of parties: the <see cref="LocalParty.Remotes"/> owned by this application and
        /// the <see cref="TenantDomains"/> with their Remotes (depth-first traversal).
        /// <para>
        /// This is a snapshot of the parties: while enumerating <see cref="IOwnedParty.IsDestroyed"/> may be
        /// true (or becomes true at any time).
        /// </para>
        /// </summary>
        IEnumerable<IOwnedParty> AllParties { get; }

        /// <summary>
        /// Gets a task that is completed once all the <see cref="IApplicationIdentityFeatureDriver"/> have been
        /// initialized. Initialization errors are set on this task if exceptions occurred: awaiting this
        /// task will re-throw the initialization errors.
        /// <para>
        /// Use <see cref="Task.IsCompletedSuccessfully"/> to know if initialization has been successful.
        /// </para>
        /// </summary>
        Task InitializationTask { get; }

        /// <summary>
        /// Gets the <see cref="ISystemClock"/> that must be used by all code related to application identities.
        /// </summary>
        ISystemClock SystemClock { get; }

        /// <summary>
        /// Raises an approximative 1 second, non reentrant, heart beat signal.
        /// <para>
        /// The period can be changed by using a specialized <see cref="ApplicationIdentityService.ISystemClock"/>.
        /// </para>
        /// </summary>
        PerfectEvent<int> Heartbeat { get; }

        /// <summary>
        /// Tries to create and initialize one or more new parties that can be tenant domains or simple
        /// remotes from a configuration section.
        /// These parties will be <see cref="IOwnedParty.IsDynamic"/> and can be destroyed.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to process.</param>
        /// <returns>The newly created tenant domains and remotes or null if an error occurred.</returns>
        Task<AddedDynamicParties?> AddPartiesAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration );

        /// <summary>
        /// Tries to create and initialize one tenant domain from a configuration section.
        /// This tenant domain will be <see cref="IOwnedParty.IsDynamic"/> and can be destroyed as well as all its remotes.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration to process.</param>
        /// <returns>The newly created tenant domain or null if an error occurred.</returns>
        Task<ITenantDomainParty?> AddTenantDomainAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration );
    }
}
