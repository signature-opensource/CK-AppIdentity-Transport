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
    /// Remotes collection configuration.
    /// </summary>
    public sealed class RemoteGroupConfiguration : ApplicationIdentityObjectConfiguration
    {
        readonly string _domainName;
        readonly string _environmentName;

        internal RemoteGroupConfiguration( ImmutableConfigurationSection configuration,
                                           string domainName,
                                           string environmentName,
                                           ApplicationIdentityObjectConfiguration[] remotes,
                                           ref InheritedConfigurationProps inhProps )
            : base( configuration, ref inhProps )
        {
            _domainName = domainName;
            _environmentName = environmentName;
            Remotes = remotes;
        }

        /// <summary>
        /// Gets the remote configurations that can be:
        /// <list type="bullet">
        ///   <item><see cref="RemotePartyConfiguration"/> for a remote party.</item>
        ///   <item><see cref="RemoteGroupConfiguration"/> for group of remotes (composite remote).</item>
        ///   <item>Base <see cref="ApplicationIdentityObjectConfiguration"/> for external remotes (when DomainName is <see cref="CoreApplicationIdentity.DefaultDomainName"/>).</item>
        /// </list>
        /// </summary>
        public IReadOnlyCollection<ApplicationIdentityObjectConfiguration> Remotes { get; }

        /// <summary>
        /// Gets the domain name resolved at this level.
        /// </summary>
        /// <remarks>
        /// This supports the <see cref="IRemoteOwner.AddDynamicRemoteAsync(IActivityMonitor, Action{MutableConfigurationSection})"/>
        /// capability of <see cref="RemoteGroup"/>.
        /// </remarks>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the environment name resolved at this level.
        /// </summary>
        /// <remarks>
        /// This supports the <see cref="IRemoteOwner.AddDynamicRemoteAsync(IActivityMonitor, Action{MutableConfigurationSection})"/>
        /// capability of <see cref="RemoteGroup"/>.
        /// </remarks>
        public string EnvironmentName => _environmentName;
    }
}
