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
    public sealed class RemotePartyConfiguration : IAppIdentityObjectConfiguration
    {
        readonly string _environmentName;
        readonly ImmutableConfigurationSection _configuration;
        readonly string _domainName;
        readonly string _name;
        readonly string? _address;
        readonly IReadOnlySet<string> _disallowFeatures;
        readonly IReadOnlySet<string> _allowFeatures;
        readonly ApplicationIdentityConfiguration? _domainConfiguration;

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
            _domainConfiguration = tenant;
        }

        internal static RemotePartyConfiguration? Create( IActivityMonitor monitor,
                                                          ImmutableConfigurationSection configuration,
                                                          string? appDomainName,
                                                          string? appEnvironmentName,
                                                          bool allowDomain,
                                                          ref InheritedConfigurationProps domainProps,
                                                          LocalPartyConfiguration? localToCheckName,
                                                          IEnumerable<RemotePartyConfiguration> remotesToCheckHomonyms )
        {
            // "Remotes" configuration handling.
            ApplicationIdentityConfiguration? domain = null;
            var remotesSection = configuration.GetSection( "Remotes" );
            bool isDomain = remotesSection.Exists();

            bool success;
            string? domainName, name, environmentName;
            if( !isDomain )
            {
                success = ApplicationIdentityConfiguration.ReadNamesWithoutFullName( monitor,
                                                                                      configuration,
                                                                                      out domainName,
                                                                                      out name,
                                                                                      out environmentName,
                                                                                      appEnvironmentName,
                                                                                      null,
                                                                                      appDomainName );
            }
            else
            {
                if( configuration["FullName"] != null )
                {
                    monitor.Error( $"Configuration '{configuration.Path}:FullName' cannot be used on a Domain (a Remote with Remotes). Only DomainName, Name or EnvironmentName can be defined." );
                    success = false;
                }
                // For a domain (a Remote with Remotes), the default Name is the domain leaf.
                // We use a fake (invalid) default here to detect the missing Name.
                success = ApplicationIdentityConfiguration.ReadNamesWithoutFullName( monitor,
                                                                                     configuration,
                                                                                     out domainName,
                                                                                     out name,
                                                                                     out environmentName,
                                                                                     appEnvironmentName,
                                                                                     "¤Fake",
                                                                                     appDomainName );
                if( name == "¤Fake" )
                {
                    int idx = domainName!.LastIndexOf( '/' );
                    name = idx < 0 ? domainName : domainName.Substring( idx + 1 );
                }
            }

            success &= InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var remoteProps );

            if( localToCheckName != null && name.Equals( localToCheckName.Name, StringComparison.OrdinalIgnoreCase ) )
            {
                monitor.Error( $"Invalid remote party name in '{configuration.Path}': '{name}' is this local name." );
                success = false;
            }
            else if( remotesToCheckHomonyms.Any( x => x.Name.Equals( name, StringComparison.OrdinalIgnoreCase ) ) )
            {
                monitor.Error( $"Duplicate remote party name in '{configuration.Path}': '{name}' remote party must be unique." );
                success = false;
            }

            if( isDomain )
            {
                using var gLog = monitor.OpenInfo( $"Detected '{remotesSection.Path}' for '{appDomainName}/{name}/{environmentName}': this remote hosts a Domain." );
                if( !allowDomain )
                {
                    monitor.Error( $"Invalid configuration '{remotesSection.Path}': domains (Remote with Remotes) can only be defined in root Remotes." );
                    success = false;
                }
                else
                {
                    // The "Undefined" domain name cannot host a domain. 
                    if( domainName == CoreApplicationIdentity.DefaultDomainName )
                    {
                        monitor.Error( $"Invalid configuration '{remotesSection.Path}': '{CoreApplicationIdentity.DefaultDomainName}' cannot host a domain. This name denotes an external system." );
                        success = false;
                    }
                    domain = ApplicationIdentityConfiguration.CreateDomain( monitor, name, environmentName, remotesSection, ref remoteProps );
                    if( domain == null ) success = false;
                }
            }
            return success
                    ? new RemotePartyConfiguration( configuration, name, domainName, environmentName, configuration["Address"], domain, ref remoteProps )
                    : null;
        }

        /// <summary>
        /// Gets the required name of this party. See <see cref="CoreApplicationIdentity.IsValidPartyName(ReadOnlySpan{char})"/>.
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
        /// Gets the domain <see cref="ApplicationIdentityConfiguration"/> if this remote
        /// hosts a domain.
        /// </summary>
        public ApplicationIdentityConfiguration? DomainConfiguration => _domainConfiguration;
    }
}
