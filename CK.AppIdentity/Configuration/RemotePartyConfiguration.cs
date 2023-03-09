using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace CK.AppIdentity
{
    public sealed class RemotePartyConfiguration
    {
        private readonly string _environmentName;
        private readonly ImmutableConfigurationSection _configuration;
        private readonly string _domainName;
        private readonly string _name;
        private readonly Uri? _uri;
        private readonly ApplicationIdentityConfiguration? _tenantAppIdentityConfiguration;

        RemotePartyConfiguration( ImmutableConfigurationSection configuration,
                                  string name,
                                  string domainName,
                                  string environmentName,
                                  Uri? uri,
                                  ApplicationIdentityConfiguration? tenant )
        {
            _configuration = configuration;
            _name = name;
            _domainName = domainName;
            _environmentName = environmentName;
            _uri = uri;
            _tenantAppIdentityConfiguration = tenant;
        }

        internal static RemotePartyConfiguration? Create( IActivityMonitor monitor,
                                                          ImmutableConfigurationSection configuration,
                                                          string? appDomainName,
                                                          string? appEnvironmentName,
                                                          bool allowDomain )
        {
            // Refrain yourself to rewrite this differently: this ensures that all properties are handled even on error.
            bool success = ApplicationIdentityConfiguration.GetName( monitor, configuration, "Name", true, null, out var name );
            if( !ApplicationIdentityConfiguration.GetName( monitor, configuration, "DomainName", false, appDomainName, out var domainName ) ) success = false;
            if( !ApplicationIdentityConfiguration.GetName( monitor, configuration, "EnvironmentName", false, appEnvironmentName, out var environmentName ) ) success = false;
            Uri? uri = null;
            var u = configuration["Uri"];
            if( !String.IsNullOrWhiteSpace( u ) && !Uri.TryCreate( configuration["Uri"], UriKind.Absolute, out uri ) )
            {
                monitor.Error( $"Unable to parse '{configuration.Path}:Uri' configuration as a valid Uri." );
                success = false;
            }
            // "Domain" configuration handling.
            ApplicationIdentityConfiguration? domain = null;
            var domainSection = configuration.GetSection( "Domain" );
            if( domainSection.Exists() )
            {
                using var gLog = monitor.OpenInfo( $"Detected '{domainSection.Path}' for '{appDomainName}/{environmentName}/{name}': this remote hosts a Domain." );
                if( !allowDomain )
                {
                    monitor.Error( $"Invalid configuration '{domainSection.Path}': domains can only be defined in root Remotes." );
                    success = false;
                }
                else
                {
                    // A remote that is the host of a Domain MUST BE in the domain of the root application.
                    if( domainName != appDomainName )
                    {
                        monitor.Error( $"Invalid '{configuration.Path}:DomainName': it can only be the root application's domain '{appDomainName}' (not '{domainName}')."
                                       + $" A remote that hosts a Domain MUST BE in the domain of the root application." );
                        success = false;
                    }
                    if( name != null
                        && environmentName != null
                        && !DomainApplicationIdentity.CheckTenantConfigurationNames( monitor, name, environmentName, domainSection ) )
                    {
                        success = false;
                    }
                    // Full analysis error may become too fragile (the configuration is already invalid).
                    // Process the domain configuration only on success.
                    if( success )
                    {
                        Debug.Assert( name != null && environmentName != null );
                        domain = ApplicationIdentityConfiguration.CreateDomain( monitor, name, environmentName, domainSection );
                        if( domain == null ) success = false;
                    }
                }
            }
            return success
                    ? new RemotePartyConfiguration( configuration, name!, domainName!, environmentName!, uri, domain )
                    : null;
        }

        /// <summary>
        /// Gets the required name of this party that must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets the uri of this party.
        /// This is null if this remote is only a client of this local application.
        /// </summary>
        public Uri? Uri => _uri;

        /// <summary>
        /// Gets the domain name of this party.
        /// This defaults to <see cref="ApplicationIdentityConfiguration.DomainName"/> but can be overridden by an explicit "DomainName"
        /// at the remote configuration level.
        /// </summary>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the environment name of this party.
        /// This defaults to <see cref="ApplicationIdentityConfiguration.EnvironmentName"/> but can be overridden by an explicit "EnvironmentName"
        /// at the remote configuration level.
        /// </summary>
        public string EnvironmentName => _environmentName;

        /// <summary>
        /// Gets the configuration for this remote.
        /// </summary>
        public ImmutableConfigurationSection Configuration => _configuration;

        /// <summary>
        /// Gets the tenant <see cref="ApplicationIdentityConfiguration"/> it there's one.
        /// </summary>
        public ApplicationIdentityConfiguration? TenantAppIdentityConfiguration => _tenantAppIdentityConfiguration;
    }
}
