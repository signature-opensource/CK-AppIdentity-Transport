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
        RemotePartyConfiguration( LockedConfigurationSection configuration,
                                  string name,
                                  string domainName,
                                  string environmentName,
                                  Uri? uri,
                                  AppIdentityConfiguration? tenant )
        {
            Configuration = configuration;
            Name = name;
            DomainName = domainName;
            EnvironmentName = environmentName;
            Uri = uri;
            TenantAppIdentityConfiguration = tenant;
        }

        internal static RemotePartyConfiguration? Create( IActivityMonitor monitor,
                                                          LockedConfigurationSection configuration,
                                                          string? appDomainName,
                                                          string? appEnvironmentName,
                                                          bool allowTenantService )
        {
            // Refrain yourself to rewrite this differently: this ensures that all properties are handled even on error.
            bool success = AppIdentityConfiguration.GetName( monitor, configuration, "Name", true, null, out var name );
            if( !AppIdentityConfiguration.GetName( monitor, configuration, "DomainName", false, appDomainName, out var domainName ) ) success = false;
            if( !AppIdentityConfiguration.GetName( monitor, configuration, "EnvironmentName", false, appEnvironmentName, out var environmentName ) ) success = false;
            Uri? uri = null;
            var u = configuration["Uri"];
            if( !String.IsNullOrWhiteSpace( u ) && !Uri.TryCreate( configuration["Uri"], UriKind.Absolute, out uri ) )
            {
                monitor.Error( $"Unable to parse '{configuration.Path}:Uri' configuration as a valid Uri." );
                success = false;
            }
            // "CK-AppIdentity" tenant handling.
            AppIdentityConfiguration? tenant = null;
            var tenantSection = configuration.GetSection( "CK-AppIdentity" );
            if( tenantSection.Exists() )
            {
                if( !allowTenantService )
                {
                    monitor.Error( $"Invalid tenant CK-AppIdentity configuration '{tenantSection.Path}': tenant application identity can only be defined in root Remotes." );
                    success = false;
                }
                else
                {
                    if( name != null
                        && environmentName != null
                        && !TenantAppIdentityService.CheckTenantConfigurationNames( monitor, name, environmentName, tenantSection ) )
                    {
                        success = false;
                    }
                    // Full analysis error may become too fragile. Process the tenant configuration only on success.
                    if( success )
                    {
                        Debug.Assert( name != null && environmentName != null );
                        tenant = AppIdentityConfiguration.CreateTenant( monitor, name, environmentName, tenantSection );
                        if( tenant == null ) success = false;
                    }
                }
            }
            return success
                    ? new RemotePartyConfiguration( configuration, name!, domainName!, environmentName!, uri, tenant )
                    : null;
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

        /// <summary>
        /// Gets the tenant <see cref="AppIdentityConfiguration"/> it there's one.
        /// </summary>
        public AppIdentityConfiguration? TenantAppIdentityConfiguration { get; }

    }
}
