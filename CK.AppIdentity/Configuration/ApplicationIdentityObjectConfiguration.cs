using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CK.AppIdentity
{

    /// <summary>
    /// Base class of all configuration objects.
    /// This is also the configuration of an external remote (when DomainName is <see cref="CoreApplicationIdentity.DefaultDomainName"/>).
    /// </summary>
    public class ApplicationIdentityObjectConfiguration
    {
        readonly ImmutableConfigurationSection _configuration;
        readonly IReadOnlySet<string> _disallowFeatures;
        readonly IReadOnlySet<string> _allowFeatures;

        internal ApplicationIdentityObjectConfiguration( ImmutableConfigurationSection configuration, ref InheritedConfigurationProps props )
        {
            _allowFeatures = props.AllowFeatures;
            _disallowFeatures = props.DisallowFeatures;
            _configuration = configuration;
        }

        /// <summary>
        /// Gets the configuration section for this object.
        /// </summary>
        public ImmutableConfigurationSection Configuration => _configuration;

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
        /// Computes whether a features is allowed at this level based on <paramref name="isAllowedAbove"/>
        /// and the content of <see cref="AllowFeatures"/> and <see cref="DisallowFeatures"/>.
        /// </summary>
        /// <param name="c">This configuration.</param>
        /// <param name="featureName">The feature name.</param>
        /// <param name="isAllowedAbove">Whether this feature is allowed by default.</param>
        /// <returns>True if the feature is allowed for this level.</returns>
        public bool IsAllowedFeature( string featureName, bool isAllowedAbove )
        {
            if( isAllowedAbove )
            {
                return !DisallowFeatures.Contains( featureName );
            }
            return AllowFeatures.Contains( featureName );
        }

        /// <summary>
        /// Creates a configuration with a "Dynamic" key that inherits from this configuration.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The dynamic configurator.</param>
        /// <param name="thisDomainName">Default domain name to use.</param>
        /// <param name="thisEnvironmentName">Default environment name to use.</param>
        /// <returns>A configuration or null if an error occurred.</returns>
        internal ApplicationIdentityObjectConfiguration? CreateDynamicRemoteConfiguration( IActivityMonitor monitor,
                                                                                           Action<MutableConfigurationSection> configuration,
                                                                                           string thisDomainName,
                                                                                           string thisEnvironmentName )
        {
            // Anchors the new mutable section below this section: lookups apply.
            // 
            // The "Remotes:X" levels are useless. We don't need these because these slots don't carry any
            // information other than the "collection" (array) and the "index" that we totally ignore.
            // 
            var anchor = Configuration;
            var remotes = new MutableConfigurationSection( anchor );
            var c = remotes.GetMutableSection( "Dynamic" );
            Debug.Assert( string.IsInterned( c.Key ) == "Dynamic" );
            configuration( c );
            var finalConfig = new ImmutableConfigurationSection( c, anchor );
            var inheritedProps = new InheritedConfigurationProps( this );
            // We obviously have a race condition here on the full name unicity.
            // The fact that no full name conflict offers no guaranty when the new configuration
            // will be added.
            // The fact that a full name conflicts is more interesting... But without more
            // concurrency guaranty.
            // We don't inject any "existing" names here: it is up to the actual add to handle
            // existing remotes.
            var fullNameIndex = new Dictionary<string, ImmutableConfigurationSection>( StringComparer.OrdinalIgnoreCase );
            return ApplicationIdentityServiceConfiguration.CreateRemote( monitor,
                                                                         finalConfig,
                                                                         thisDomainName,
                                                                         thisEnvironmentName,
                                                                         ref inheritedProps,
                                                                         fullNameIndex );
        }

        public override string ToString() => $"{GetType().Name} - {_configuration.ToString()}";

        #region Names reading
        private protected enum NameKind
        {
            Domain,
            Party,
            Env
        }

        static readonly string[] _names = new[] { "DomainName", "PartyName", "EnvironmentName" };

        static readonly string[] _nameSyntaxes = new[]
        {
            $"must be a case sensitive identifier or path of identifiers not longer than {CoreApplicationIdentity.DomainNameMaxLength}, "
            + $"no leading or trailing '/' and no double '//' are allowed. Identifier should use PascalCase convention if possible and must "
            + $"only contain 'A'-'Z', 'a'-'z', '0'-'9', '-' and '_' characters and must not start with a digit, and not start or end with '_' or '-'.",

            $"should use PascalCase convention if possible and must only contain 'A'-'Z', 'a'-'z', '0'-'9', '-' and '_' characters and "
            + $"must not start with a digit, and not start or end with '_' or '-' or be longer than {CoreApplicationIdentity.PartyNameMaxLength}.",

            $"must start with a '#', should use PascalCase convention if possible and must only contain 'A'-'Z', 'a'-'z', '0'-'9', '-' and '_'  "
            + $"or be longer than {CoreApplicationIdentity.EnvironmentNameMaxLength}."
        };

        private protected static bool ReadNames( IActivityMonitor monitor,
                                                 ImmutableConfigurationSection s,
                                                 out string domainName,
                                                 out string partyName,
                                                 out string environmentName,
                                                 string? defaultDomainName = null,
                                                 string? defaultPartyName = null,
                                                 string? defaultEnvironmentName = null )
        {
            var f = s["FullName"];
            if( f != null )
            {
                return ReadFromFullName( monitor, s, f, out domainName, out partyName, out environmentName, defaultEnvironmentName );
            }
            // No shortcut operators here to collect all the errors.
            return ReadName( monitor, s, NameKind.Domain, out domainName, defaultDomainName )
                   & ReadName( monitor, s, NameKind.Party, out partyName, defaultPartyName )
                   & ReadName( monitor, s, NameKind.Env, out environmentName, defaultEnvironmentName );

            static bool ReadFromFullName( IActivityMonitor monitor,
                                          ImmutableConfigurationSection s,
                                          string fullName,
                                          out string domainName,
                                          out string partyName,
                                          out string environmentName,
                                          string? defaultEnvironmentName )
            {
                if( !CoreApplicationIdentity.TryParseFullName( fullName, out var d, out var p, out var e ) )
                {
                    monitor.Error( $"Invalid '{s.Path}:FullName'. '{fullName}' is not a valid party full name." );
                    domainName = partyName = environmentName = "<error>";
                    return false;
                }
                bool success = true;
                if( p == null )
                {
                    monitor.Error( $"Configuration '{s.Path}:FullName' must contain a $PartyName segment." );
                    p = "<error>";
                    success = false;
                }
                if( s["DomainName"] != null )
                {
                    monitor.Error( $"'{s.Path}:DomainName' cannot be used when '{s.Path}:FullName' is defined." );
                    success = false;
                }
                if( s["Name"] != null )
                {
                    monitor.Error( $"'{s.Path}:Name' cannot be used when '{s.Path}:FullName' is defined." );
                    success = false;
                }
                if( e == null )
                {
                    success &= ReadName( monitor, s, NameKind.Env, out e, defaultEnvironmentName );
                }
                else if( s["EnvironmentName"] != null )
                {
                    monitor.Error( $"'{s.Path}:EnvironmentName' cannot be used when '{s.Path}:FullName' defines it." );
                    success = false;
                }
                domainName = d;
                partyName = p;
                environmentName = e;
                return success;
            }
        }

        private protected static bool ReadName( IActivityMonitor monitor, ImmutableConfigurationSection s, NameKind kind, out string name, string? defaultName )
        {
            var k = _names[(int)kind];
            var n = s[k];
            if( n != null )
            {
                bool isValid = kind switch
                {
                    NameKind.Domain => CoreApplicationIdentity.IsValidDomainName( n ),
                    NameKind.Party => CoreApplicationIdentity.IsValidPartyName( n ),
                    NameKind.Env => CoreApplicationIdentity.IsValidEnvironmentName( n ),
                    _ => Throw.NotSupportedException<bool>()
                };
                if( !isValid )
                {
                    monitor.Error( $"Invalid '{s.Path}:{k}'. It {_nameSyntaxes[(int)NameKind.Env]}" );
                    name = "<error>";
                    return false;
                }
                name = n;
            }
            else
            {
                if( defaultName == null )
                {
                    monitor.Error( $"Configuration '{s.Path}:{k}' is required." );
                    name = "<error>";
                    return false;
                }
                name = defaultName;
            }
            return true;
        }
        #endregion
    }
}
