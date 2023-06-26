using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace CK.AppIdentity
{

    /// <summary>
    /// A PartyGroupConfiguration has no PartyName (it is not a Party).
    /// Its <see cref="Parties"/> are base <see cref="ApplicationIdentityObjectConfiguration"/> because
    /// it can contain other PartyGroupConfiguration.
    /// </summary>
    public sealed class PartyGroupConfiguration : ApplicationIdentityObjectConfiguration
    {
        readonly string _domainName;
        readonly string _environmentName;

        internal PartyGroupConfiguration( ImmutableConfigurationSection configuration,
                                          string domainName,
                                          string environmentName,
                                          ApplicationIdentityObjectConfiguration[] parties,
                                          ref InheritedConfigurationProps inhProps )
            : base( configuration, ref inhProps )
        {
            _domainName = domainName;
            _environmentName = environmentName;
            Parties = parties;
        }

        /// <summary>
        /// Gets the subordinated configurations that can be:
        /// <list type="bullet">
        ///   <item><see cref="RemotePartyConfiguration"/> for a remote or external party.</item>
        ///   <item><see cref="DomainPartyConfiguration"/> for local domain controller parties.</item>
        ///   <item>Another <see cref="PartyGroupConfiguration"/> for group of parties (that is not a Party).</item>
        /// </list>
        /// </summary>
        public IReadOnlyCollection<ApplicationIdentityObjectConfiguration> Parties { get; }

        /// <summary>
        /// Gets the domain name resolved at this level.
        /// </summary>
        /// <remarks>
        /// This supports the <see cref="IRemoteOwner.AddDynamicRemoteAsync(IActivityMonitor, Action{MutableConfigurationSection})"/>
        /// capability of a <see cref="PartyGroup"/>.
        /// </remarks>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the environment name resolved at this level.
        /// </summary>
        /// <remarks>
        /// This supports the <see cref="IRemoteOwner.AddDynamicRemoteAsync(IActivityMonitor, Action{MutableConfigurationSection})"/>
        /// capability of a <see cref="PartyGroup"/>.
        /// </remarks>
        public string EnvironmentName => _environmentName;
    }
}
