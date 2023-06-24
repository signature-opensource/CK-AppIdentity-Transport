using CK.Core;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace CK.AppIdentity
{


    /// <summary>
    /// Local identity is defined at least by the <see cref="Name"/>.
    /// </summary>
    public sealed class LocalPartyConfiguration : IAppIdentityObjectConfiguration
    {
        readonly string _name;
        readonly IReadOnlySet<string> _disallowFeatures;
        readonly IReadOnlySet<string> _allowFeatures;

        LocalPartyConfiguration( ImmutableConfigurationSection configuration, string name, ref InheritedConfigurationProps props )
        {
            Debug.Assert( CoreApplicationIdentity.IsValidPartyName( name ) );
            Debug.Assert( props.IsValid );
            Configuration = configuration;
            _name = name[0] == '$' ? name.Substring( 1 ) : name;
            _allowFeatures = props.AllowFeatures;
            _disallowFeatures = props.DisallowFeatures;
        }

        internal static LocalPartyConfiguration? Create( IActivityMonitor monitor,
                                                         ImmutableConfigurationSection configuration,
                                                         string domainName,
                                                         string? applicationName,
                                                         ref InheritedConfigurationProps inheritedProps )
        {
            // TryCreate handles the fact that inheritedProps may be invalid.
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var props );

            string name;
            if( applicationName != null )
            {
                name = applicationName;
                success &= CheckNotExist( monitor, configuration, "Name", $"the application name '{name}' is already defined above" );
            }
            else
            {
                int idx = domainName.IndexOf( "/" );
                var defName = idx < 0 ? domainName : domainName.Substring( idx + 1 );
                success &= ApplicationIdentityConfiguration.ReadName( monitor, configuration, ApplicationIdentityConfiguration.NameKind.Party, out name, defName );
            }

            const string noKeyReason = "application 'Local' can only define the Name";
            // Caution: we use non short-circuiting & here!
            success &= CheckNotExist( monitor, configuration, "FullName", noKeyReason )
                       & CheckNotExist( monitor, configuration, "DomainName", noKeyReason )
                       & CheckNotExist( monitor, configuration, "EnvironmentName", noKeyReason );

            return success ? new LocalPartyConfiguration( configuration, name, ref props ) : null;
        }

        internal static LocalPartyConfiguration? CreateDomainLocal( IActivityMonitor monitor,
                                                                    ImmutableConfigurationSection configuration,
                                                                    string remoteName,
                                                                    ref InheritedConfigurationProps inheritedProps )
        {
            const string noKeyReason = "all naming of a domain 'Local' is given by the Remote definition above";
            // Caution: we use non short-circuiting & here!
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var props )
                           & CheckNotExist( monitor, configuration, "FullName", noKeyReason )
                           & CheckNotExist( monitor, configuration, "DomainName", noKeyReason )
                           & CheckNotExist( monitor, configuration, "Name", noKeyReason )
                           & CheckNotExist( monitor, configuration, "EnvironmentName", noKeyReason );
            return success ? new LocalPartyConfiguration( configuration, remoteName, ref props ) : null;
        }

        internal static bool CheckNotExist( IActivityMonitor monitor, ImmutableConfigurationSection configuration, string key, string reason )
        {
            if( configuration[key] != null )
            {
                monitor.Error( $"Invalid '{configuration.Path}:{key}' key: {reason}." );
                return false;
            }
            return true;
        }

        /// <summary>
        /// Gets a required name of this local application.
        /// It must be an identifier: see <see cref="CoreApplicationIdentity.PartyName"/>.
        /// </summary>
        public string Name => _name;

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
        /// Gets the "CK-AppIdentity:Local" configuration section.
        /// </summary>
        public ImmutableConfigurationSection Configuration { get; }

    }
}
