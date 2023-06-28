using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Captures the result of a dynamic configuration processing.
    /// <para>
    /// See <see cref="IApplicationIdentityService.AddPartiesAsync(IActivityMonitor, Action{MutableConfigurationSection})"/>.
    /// </para>
    /// </summary>
    /// <param name="Remotes">The list of added remotes.</param>
    /// <param name="Tenants">The list of added tenant domains.</param>
    public readonly record struct AddedDynamicParties( IReadOnlyCollection<IRemoteParty> Remotes, IReadOnlyCollection<ITenantDomainParty> Tenants )
    {
        /// <summary>
        /// Gets the remotes and tenants count.
        /// </summary>
        public int Count => Remotes.Count + Tenants.Count;

        /// <summary>
        /// Gets the remotes and the tenants.
        /// </summary>
        public IEnumerable<IOwnedParty> Parties => ((IEnumerable<IOwnedParty>)Remotes).Concat( Tenants );
    }
}
