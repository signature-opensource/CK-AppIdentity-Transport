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
    public sealed class LocalPartyConfiguration
    {
        readonly string _name;
        readonly IReadOnlySet<string> _disallowFeatures;
        readonly IReadOnlySet<string> _allowFeatures;

        LocalPartyConfiguration( ImmutableConfigurationSection configuration, string name, ref InheritedConfigurationProps props )
        {
            Debug.Assert( CoreApplicationIdentity.IsValidIdentifier( name ) );
            Debug.Assert( props.IsValid );
            Configuration = configuration;
            _name = name;
            _allowFeatures = props.AllowFeatures;
            _disallowFeatures = props.DisallowFeatures;
        }

        internal static LocalPartyConfiguration? Create( IActivityMonitor monitor,
                                                         ImmutableConfigurationSection configuration,
                                                         string? applicationName,
                                                         ref InheritedConfigurationProps inheritedProps )
        {
            // TryCreate handles the fact that inheritedProps may be invalid.
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var props );

            if( !ApplicationIdentityConfiguration.GetName( monitor, configuration, "Name", false, applicationName, out var name ) ) success = false;

            return success ? new LocalPartyConfiguration( configuration, name!, ref props ) : null;
        }

        internal static LocalPartyConfiguration? CreateDomainLocal( IActivityMonitor monitor,
                                                                    ImmutableConfigurationSection configuration,
                                                                    string remoteName,
                                                                    ref InheritedConfigurationProps inheritedProps )
        {
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var props );
            return success ? new LocalPartyConfiguration( configuration, remoteName, ref props ) : null;
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
