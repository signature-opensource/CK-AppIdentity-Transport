using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CK.AppIdentity
{
    public sealed class RemotePartyConfiguration
    {
        readonly string _environmentName;
        readonly ImmutableConfigurationSection _configuration;
        readonly string _domainName;
        readonly string _name;
        readonly string? _address;
        readonly IReadOnlySet<string> _disallowFeatures;
        readonly IReadOnlySet<string> _allowFeatures;
        readonly ApplicationIdentityConfiguration? _tenantAppIdentityConfiguration;

        RemotePartyConfiguration( ImmutableConfigurationSection configuration,
                                  string name,
                                  string domainName,
                                  string environmentName,
                                  string? address,
                                  ApplicationIdentityConfiguration? tenant,
                                  ref InheritedConfigurationProps remoteProps )
        {
            _configuration = configuration;
            _name = name;
            _domainName = domainName;
            _environmentName = environmentName;
            _address = address;
            _allowFeatures = remoteProps.AllowFeatures;
            _disallowFeatures = remoteProps.DisallowFeatures;
            _tenantAppIdentityConfiguration = tenant;
        }

        internal static RemotePartyConfiguration? Create( IActivityMonitor monitor,
                                                          ImmutableConfigurationSection configuration,
                                                          string? appDomainName,
                                                          string? appEnvironmentName,
                                                          bool allowDomain,
                                                          ref InheritedConfigurationProps domainProps )
        {
            // Refrain yourself to rewrite this differently: this ensures that all properties are handled even on error.
            bool success = ApplicationIdentityConfiguration.GetName( monitor, configuration, "Name", true, null, out var name );
            if( !ApplicationIdentityConfiguration.GetName( monitor, configuration, "DomainName", false, appDomainName, out var domainName, true ) ) success = false;
            if( !ApplicationIdentityConfiguration.GetName( monitor, configuration, "EnvironmentName", false, appEnvironmentName, out var environmentName ) ) success = false;
            if( !InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var remoteProps ) ) success = false;

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
                        domain = ApplicationIdentityConfiguration.CreateDomain( monitor, name, environmentName, domainSection, ref remoteProps );
                        if( domain == null ) success = false;
                    }
                }
            }
            return success
                    ? new RemotePartyConfiguration( configuration, name!, domainName!, environmentName!, configuration["Address"], domain, ref remoteProps )
                    : null;
        }

        /// <summary>
        /// Gets the required name of this party. See <see cref="CoreApplicationIdentity.IsValidIdentifier(ReadOnlySpan{char})"/>.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => _address;

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
        /// Gets a set of feature names that are disabled at this level.
        /// No duplicate and no <see cref="AllowFeatures"/> must appear in this set.
        /// </summary>
        public IReadOnlySet<string> DisallowFeatures => _disallowFeatures;

        /// <summary>
        /// Gets a set of feature names that are enabled at this level.
        /// No duplicate and no <see cref="DisallowFeatures"/> must appear in this set.
        /// </summary>
        public IReadOnlySet<string> AllowFeatures => _allowFeatures;

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
