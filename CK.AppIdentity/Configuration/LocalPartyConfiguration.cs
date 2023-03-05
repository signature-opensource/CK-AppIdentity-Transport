using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.AppIdentity
{
    /// <summary>
    /// Local identity is defined at least by the <see cref="Name"/>.
    /// </summary>
    public sealed class LocalPartyConfiguration
    {
        internal LocalPartyConfiguration( LockedConfigurationSection configuration, string name )
        {
            Configuration = configuration;
            Name = name;
        }

        internal static LocalPartyConfiguration? Create( IActivityMonitor monitor, LockedConfigurationSection configuration, string applicationName )
        {
            return AppIdentityConfiguration.GetName( monitor, configuration, "Name", false, applicationName, out var name )
                    ? new LocalPartyConfiguration( configuration, name! )
                    : null;
        }

        /// <summary>
        /// Gets a required name of this local application.
        /// It must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the "CK-AppIdentity:Local" configuration section.
        /// </summary>
        public LockedConfigurationSection Configuration { get; }

    }
}
