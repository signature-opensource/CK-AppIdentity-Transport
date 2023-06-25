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
    /// Remotes collection configuration is the base of the root <see cref="ApplicationIdentityServiceConfiguration"/>
    /// and the configuration of a composite remote.
    /// </summary>
    public class RemoteCollectionConfiguration : ApplicationIdentityBaseConfiguration
    {
        internal RemoteCollectionConfiguration( ImmutableConfigurationSection configuration,
                                                string domainName,
                                                string fullName,
                                                ApplicationIdentityBaseConfiguration[] remotes,
                                                ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, ref inhProps )
        {
            Remotes = remotes;
        }

        /// <summary>
        /// Gets the set of remotes configuration.
        /// </summary>
        public IReadOnlyCollection<ApplicationIdentityBaseConfiguration> Remotes { get; }

    }
}
