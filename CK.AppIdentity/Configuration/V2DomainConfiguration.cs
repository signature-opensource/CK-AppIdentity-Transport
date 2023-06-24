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
    /// It is also the base of the root <see cref="V2ApplicationIdentityService"/>.
    /// </summary>
    public class V2DomainConfiguration : V2AppIdentityObjectConfiguration
    {
        internal V2DomainConfiguration( ImmutableConfigurationSection configuration,
                                      string domainName,
                                      string fullName,
                                      V2LocalPartyConfiguration local,
                                      V2AppIdentityObjectConfiguration[] remotes,
                                      ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, ref inhProps )
        {
            Local = local;
            Remotes = remotes;
        }

        /// <summary>
        /// Gets the local party. Its <see cref="V2LocalPartyConfiguration.PartyName"/> is the
        /// domain leaf name.
        /// </summary>
        public V2LocalPartyConfiguration Local { get; }

        /// <summary>
        /// Gets the set of remotes configuration.
        /// </summary>
        public IReadOnlyCollection<V2AppIdentityObjectConfiguration> Remotes { get; }

    }
}
