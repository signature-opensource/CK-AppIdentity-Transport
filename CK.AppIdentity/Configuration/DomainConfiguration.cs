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
    /// A Remote with Remotes is a remote domain.
    /// It is also the base of the root <see cref="ApplicationIdentityService"/>.
    /// </summary>
    public class DomainConfiguration : AppIdentityObjectConfiguration
    {
        internal DomainConfiguration( ImmutableConfigurationSection configuration,
                                      string domainName,
                                      string fullName,
                                      LocalPartyConfiguration local,
                                      AppIdentityObjectConfiguration[] remotes,
                                      ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, ref inhProps )
        {
            Local = local;
            Remotes = remotes;
        }

        /// <summary>
        /// Gets the local party. Its <see cref="LocalPartyConfiguration.PartyName"/> is the
        /// domain leaf name.
        /// </summary>
        public LocalPartyConfiguration Local { get; }

        /// <summary>
        /// Gets the set of remotes configuration.
        /// </summary>
        public IReadOnlyCollection<AppIdentityObjectConfiguration> Remotes { get; }

    }
}
