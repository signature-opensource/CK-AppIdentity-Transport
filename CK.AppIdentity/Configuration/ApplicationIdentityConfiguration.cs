using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace CK.AppIdentity
{
    /// <summary>
    /// Configuration that defines the identity of an application.
    /// This is designed to be available as a singleton service in the DI container (the package CK.AppIdentity.Configuration does that).
    /// </summary>
    public sealed class ApplicationIdentityConfiguration : IAppIdentityObjectConfiguration
    {
        ApplicationIdentityConfiguration( ImmutableConfigurationSection configuration,
                                          string domainName,
                                          string environmentName,
                                          LocalPartyConfiguration local,
                                          RemotePartyConfiguration[] remotes,
                                          ref InheritedConfigurationProps inhProps )
        {
            Configuration = configuration;
            DomainName = domainName;
            EnvironmentName = environmentName;
            Local = local;
            Remotes = remotes;
            AllowFeatures = inhProps.AllowFeatures;
            DisallowFeatures = inhProps.DisallowFeatures;
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a <see cref="IConfigurationSection"/>
        /// and the <see cref="IHostEnvironment"/> for the defaults <see cref="IHostEnvironment.ApplicationName"/>
        /// and <see cref="IHostEnvironment.EnvironmentName"/>.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="hostEnvironment">The hosting environment from which defaults local and environment names are used.</param>
        /// <param name="configuration">The configuration section (typically named "CK-AppIdentity").</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityConfiguration? Create( IActivityMonitor monitor, IHostEnvironment hostEnvironment, IConfigurationSection configuration )
        {
            return Create( monitor, configuration, hostEnvironment.ApplicationName, hostEnvironment.EnvironmentName );
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a "CK-AppIdentity" <see cref="MutableConfigurationSection"/>
        /// that is setup by a callback. At least "Local:Name" configuration must be set ("EnvironmentName" defaults to "Development").
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">Must configure the "CK-AppIdentity" section.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityConfiguration? Create( IActivityMonitor monitor,
                                                                Action<MutableConfigurationSection> configuration )
        {
            var c = new MutableConfigurationSection( "CK-AppIdentity" );
            configuration( c );
            return Create( monitor, c );
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a <see cref="IConfigurationSection"/>.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">The configuration section (typically named "CK-AppIdentity").</param>
        /// <param name="defaultLocalName">A valid local name to use if the <paramref name="configuration"/> doesn't specify the "Local:Name".</param>
        /// <param name="defaultEnvironmentName">A valid environment name to use if the <paramref name="configuration"/> doesn't specify it.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityConfiguration? Create( IActivityMonitor monitor,
                                                                IConfigurationSection configuration,
                                                                string? defaultLocalName = null,
                                                                string? defaultEnvironmentName = "Development" )
        {
            using var gLog = monitor.OpenInfo( "Creating root AppIdentityConfiguration service." );
            var root = configuration as ImmutableConfigurationSection ?? new ImmutableConfigurationSection( configuration );
            bool success = GetName( monitor, root, "DomainName", false, "Default", out var domainName, true );
            if( domainName == CoreApplicationIdentity.DefaultDomainName )
            {
                monitor.Error( $"Root domain name cannot be '{CoreApplicationIdentity.DefaultDomainName}'. This name denotes an external system." );
                success = false;
            }
            if( !GetName( monitor, root, "EnvironmentName", false, defaultEnvironmentName, out var environmentName ) ) success = false;

            if( !InheritedConfigurationProps.TryCreate( monitor, root, out var inheritedProps ) ) success = false;

            var local = LocalPartyConfiguration.Create( monitor, root.GetSection( "Local" ), defaultLocalName, ref inheritedProps );
            if( local == null ) success = false;

            // Always try to create the remotes even if success is already false: this enables
            // configuration errors to be fixed at once.
            var c = CreateRemotes( monitor, root, domainName, environmentName, local, allowDomains: true, ref inheritedProps );
            if( !success ) c = null;
            if( c == null ) monitor.CloseGroup( "Failed." );
            return c;
        }

        internal static ApplicationIdentityConfiguration? CreateDomain( IActivityMonitor monitor,
                                                                        string remoteName,
                                                                        string remoteEnvironmentName,
                                                                        ImmutableConfigurationSection configuration,
                                                                        ref InheritedConfigurationProps inheritedProps )
        {
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var domainProps );
            var local = LocalPartyConfiguration.CreateDomainLocal( monitor, configuration.GetSection( "Local" ), remoteName, ref domainProps );
            var c = CreateRemotes( monitor, configuration, remoteName, remoteEnvironmentName, local, allowDomains: false, ref domainProps );
            return success ? c : null;
        }

        private static ApplicationIdentityConfiguration? CreateRemotes( IActivityMonitor monitor,
                                                                        ImmutableConfigurationSection locked,
                                                                        string? domainName,
                                                                        string? environmentName,
                                                                        LocalPartyConfiguration? local,
                                                                        bool allowDomains,
                                                                        ref InheritedConfigurationProps domainProps )
        {
            bool success = domainName != null && environmentName!= null && local != null && domainProps.IsValid;
            var remotes = new List<RemotePartyConfiguration>();
            foreach( var c in locked.GetSection( "Remotes" ).GetChildren() )
            {
                var r = RemotePartyConfiguration.Create( monitor, c, domainName!, environmentName!, allowDomains, ref domainProps );
                if( r == null ) success = false;
                else
                {
                    if( local != null && r.Name.Equals( local.Name, StringComparison.OrdinalIgnoreCase ) )
                    {
                        monitor.Error( $"Invalid remote party name in '{c.Path}': '{r.Name}' is this local name." );
                        success = false;
                    }
                    else if( remotes.Any( x => x.Name.Equals( r.Name, StringComparison.OrdinalIgnoreCase ) ) )
                    {
                        monitor.Error( $"Duplicate remote party name in '{c.Path}': '{r.Name}' remote party must be unique." );
                        success = false;
                    }
                    if( success ) remotes.Add( r );
                }
            }
            return success
                    ? new ApplicationIdentityConfiguration( locked, domainName!, environmentName!, local!, remotes.ToArray(), ref domainProps )
                    : null;
        }

        /// <summary>
        /// Gets the "CK-AppIdentity" configuration section.
        /// </summary>
        public ImmutableConfigurationSection Configuration { get; }

        /// <summary>
        /// Gets the name of the domain to which this application belongs.
        /// It cannot be null or empty and defaults to "Undefined".
        /// <para>
        /// See <see cref="CoreApplicationIdentity.DomainName"/>.
        /// </para>
        /// </summary>
        public string DomainName { get; }

        /// <summary>
        /// Gets the name of the environment. See <see cref="CoreApplicationIdentity.EnvironmentName"/>.
        /// </summary>
        public string EnvironmentName { get; }

        /// <summary>
        /// Gets the this configured local identity (this holds the <see cref="LocalPartyConfiguration.Name"/> of this application).
        /// </summary>
        public LocalPartyConfiguration Local { get; }

        /// <summary>
        /// Gets a set of feature names that are disabled at this level.
        /// No duplicate and no <see cref="AllowFeatures"/> must appear in this set.
        /// </summary>
        public IReadOnlySet<string> DisallowFeatures { get; }

        /// <summary>
        /// Gets a set of feature names that are enabled at this level.
        /// No duplicate and no <see cref="DisallowFeatures"/> must appear in this set.
        /// </summary>
        public IReadOnlySet<string> AllowFeatures { get; }

        /// <summary>
        /// Gets the set of the configured remotes.
        /// </summary>
        public IReadOnlyCollection<RemotePartyConfiguration> Remotes { get; }


        /// <summary>
        /// Helper that reads a string array from a string value, a comma separated string, or children
        /// sections (with string value or comma separated string) that must have integer keys ("0", "1",...).
        /// Returns null on error (and the error is logged).
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="s">The section.</param>
        /// <param name="key">The configuration key.</param>
        /// <returns>The string array or null on error.</returns>
        public static string[]? ReadStringArray( IActivityMonitor monitor, ImmutableConfigurationSection s, string key )
        {
            var section = s.TryGetSection( key );
            if( section != null )
            {
                if( section.Value != null )
                {
                    return section.Value.Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.RemoveEmptyEntries );
                }
                var result = new List<string>();
                foreach( var o in section.GetChildren() )
                {
                    var value = o.Value;
                    if( value == null || !int.TryParse( o.Key, out _ ) )
                    {
                        monitor.Error( $"Invalid array configuration for '{section.Path}': key '{o.Path}' is invalid." );
                        return null;
                    }
                    if( string.IsNullOrEmpty( value ) ) continue;
                    if( value.Contains( ',' ) ) result.AddRangeArray( value.Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.RemoveEmptyEntries ) );
                    else
                    {
                        value = value.Trim();
                        if( value.Length > 0 ) result.Add( value );
                    }
                }
                return result.ToArray();
            }
            return Array.Empty<string>();
        }

        /// <summary>
        /// Calls <see cref="ReadStringArray(IActivityMonitor, ImmutableConfigurationSection, string)"/> and ensures that
        /// strings are unique.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="s">The section.</param>
        /// <param name="key">The configuration key.</param>
        /// <param name="comparer">Optional comparer.</param>
        /// <returns>A set of unique strings or null on error.</returns>
        public static HashSet<string>? ReadUniqueStringSet( IActivityMonitor monitor, ImmutableConfigurationSection s, string key, StringComparer? comparer = null )
        {
            var a = ReadStringArray( monitor, s, key );
            if( a == null ) return null;
            var set = new HashSet<string>( a, comparer );
            if( set.Count != a.Length )
            {
                monitor.Error( $"Duplicate found in '{s.Path}:{key}': {a.Except( set ).Concatenate()}." );
                return null;
            }
            return set;
        }

        /// <summary>
        /// Emits an error if the configuration key exists and returns true.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="s">The section.</param>
        /// <param name="key">The configuration key.</param>
        /// <param name="reasonPhrase">The reason why this property must not be defined here.</param>
        /// <returns>True if there is an error.</returns>
        public static bool ErrorOnProperty( IActivityMonitor monitor, ImmutableConfigurationSection configuration, string key, string reasonPhrase )
        {
            if( configuration.TryGetSection( key ) != null )
            {
                monitor.Error( $"Configuration '{configuration.Path}:{key}' cannot be defined here. {reasonPhrase}" );
                return true;
            }
            return false;
        }

        const string _identifierSyntax = " must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters and must not start with a digit nor a '_'";
        const string _nameSuffix = $" must be an identifier: it{_identifierSyntax}.";
        const string _pathSuffix = $" must be an identifier or a path of identifiers: each identifier{_identifierSyntax}, no leading or trailing '/' and no double '//' are allowed.";

        internal static bool GetName( IActivityMonitor monitor,
                                      IConfigurationSection configuration,
                                      string propertyName,
                                      bool isRequired,
                                      string? defaultValue,
                                      [NotNullWhen( true )] out string? value,
                                      bool isDomainName = false )
        {
            value = configuration[propertyName];
            if( !ValidateName( monitor, propertyName, ref value, isRequired, isDomainName ) )
            {
                return false;
            }
            if( value == null && defaultValue != null )
            {
                if( !ValidateName( monitor, $"default value for '{propertyName}'", ref defaultValue, true, isDomainName ) ) return false;
                monitor.Info( $"Undefined configuration property '{configuration.Path}:{propertyName}'. Using default value '{defaultValue}'." );
                value = defaultValue;
            }
            Debug.Assert( value != null );
            return true;
        }

        static bool ValidateName( IActivityMonitor monitor, string propertyName, ref string? value, bool isRequired, bool isDomainName )
        {
            if( string.IsNullOrWhiteSpace( value ) )
            {
                if( isRequired )
                {
                    monitor.Error( $"{propertyName} is required and{_nameSuffix}" );
                    return false;
                }
                value = null;
                return true;
            }
            bool isValid = isDomainName
                            ? CoreApplicationIdentity.IsValidDomainName( value )
                            : CoreApplicationIdentity.IsValidIdentifier( value );
            if( !isValid )
            {
                monitor.Error( $"{propertyName}: '{value}'{(isDomainName ? _pathSuffix : _nameSuffix)}." );
                return false;
            }
            return true;
        }
    }
}
