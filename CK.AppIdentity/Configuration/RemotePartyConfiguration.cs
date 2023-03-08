using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace CK.AppIdentity
{
    public sealed class RemotePartyConfiguration
    {
        RemotePartyConfiguration( LockedConfigurationSection configuration, string name, string domainName, string environmentName, Uri? uri )
        {
            Configuration = configuration;
            Name = name;
            DomainName = domainName;
            EnvironmentName = environmentName;
            Uri = uri;
        }

        internal static RemotePartyConfiguration? Create( IActivityMonitor monitor, LockedConfigurationSection configuration, string appDomainName, string appEnvironmentName )
        {
            // Refrain yourself to rewrite this differently: this ensures that all properties are handled even on error.
            bool success = AppIdentityConfiguration.GetName( monitor, configuration, "Name", true, null, out var name );
            if( !AppIdentityConfiguration.GetName( monitor, configuration, "DomainName", false, appDomainName, out var domainName ) ) success = false;
            if( !AppIdentityConfiguration.GetName( monitor, configuration, "EnvironmentName", false, appEnvironmentName, out var environmentName ) ) success = false;
            Uri? uri = null;
            var u = configuration["Uri"];
            if( !String.IsNullOrWhiteSpace( u ) && !Uri.TryCreate( configuration["Uri"], UriKind.Absolute, out uri ) ) success = false;
            return success ? new RemotePartyConfiguration( configuration, name!, domainName!, environmentName!, uri ) : null;
        }

        /// <summary>
        /// Gets the required name of this party that must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the uri of this party.
        /// This is null if this remote is only a client of this local application.
        /// </summary>
        public Uri? Uri { get; }

        /// <summary>
        /// Gets the domain name of this party.
        /// This defaults to <see cref="AppIdentityConfiguration.DomainName"/> but can be overridden by an explicit "DomainName"
        /// at the remote configuration level.
        /// </summary>
        public string DomainName { get; }

        /// <summary>
        /// Gets the environment name of this party.
        /// This defaults to <see cref="AppIdentityConfiguration.EnvironmentName"/> but can be overridden by an explicit "EnvironmentName"
        /// at the remote configuration level.
        /// </summary>
        public string EnvironmentName { get; }

        /// <summary>
        /// Gets the configuration for this remote.
        /// </summary>
        public LockedConfigurationSection Configuration { get; }


    }
}
