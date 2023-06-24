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
        public static ApplicationIdentityConfiguration? Create( IActivityMonitor monitor,
                                                                IHostEnvironment hostEnvironment,
                                                                IConfigurationSection configuration )
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
        /// <param name="defaultLocalName">A valid local name to use if the <paramref name="configuration"/> doesn't specify "Name" or the "Local:Name".</param>
        /// <param name="defaultEnvironmentName">A valid environment name to use if the <paramref name="configuration"/> doesn't specify it.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityConfiguration? Create( IActivityMonitor monitor,
                                                                IConfigurationSection configuration,
                                                                string? defaultLocalName = null,
                                                                string defaultEnvironmentName = CoreApplicationIdentity.DefaultEnvironmentName )
        {
            Throw.CheckNotNullArgument( defaultEnvironmentName );
            using var gLog = monitor.OpenInfo( "Creating root AppIdentityConfiguration service." );
            var root = configuration as ImmutableConfigurationSection ?? new ImmutableConfigurationSection( configuration );

            defaultLocalName ??= "¤MayBeInLocal";
            bool success = ReadNames( monitor, root, out var domainName, out var name, out var environmentName, null, defaultLocalName, defaultEnvironmentName );
            if( name == "¤MayBeInLocal" ) name = null;

            success &= InheritedConfigurationProps.TryCreate( monitor, root, out var inheritedProps );

            var local = LocalPartyConfiguration.Create( monitor, root.GetSection( "Local" ), domainName, name, ref inheritedProps );
            if( local == null ) success = false;

            if( domainName == CoreApplicationIdentity.DefaultDomainName )
            {
                monitor.Error( $"Root domain name cannot be '{CoreApplicationIdentity.DefaultDomainName}'. This name denotes an external system." );
                success = false;
            }
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
            Debug.Assert( remoteName != null && remoteEnvironmentName != null );
            bool success = InheritedConfigurationProps.TryCreate( monitor, inheritedProps, configuration, out var domainProps );
            var local = LocalPartyConfiguration.CreateDomainLocal( monitor, configuration.GetSection( "Local" ), remoteName, ref domainProps );
            var c = CreateRemotes( monitor, configuration, remoteName, remoteEnvironmentName, local, allowDomains: false, ref domainProps );
            return success ? c : null;
        }

        private static ApplicationIdentityConfiguration? CreateRemotes( IActivityMonitor monitor,
                                                                        ImmutableConfigurationSection locked,
                                                                        string domainName,
                                                                        string environmentName,
                                                                        LocalPartyConfiguration? local,
                                                                        bool allowDomains,
                                                                        ref InheritedConfigurationProps domainProps )
        {
            bool success = local != null && domainProps.IsValid;
            var remotes = new List<RemotePartyConfiguration>();
            foreach( var c in locked.GetSection( "Remotes" ).GetChildren() )
            {
                var r = RemotePartyConfiguration.Create( monitor, c, domainName, environmentName, allowDomains, ref domainProps, local, remotes );
                if( r == null ) success = false;
                else if( success ) remotes.Add( r );
            }
            return success
                    ? new ApplicationIdentityConfiguration( locked, domainName, environmentName, local!, remotes.ToArray(), ref domainProps )
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
        /// <returns>The string array (empty if the key doesn't exist) or null on error.</returns>
        public static string[]? ReadStringArray( IActivityMonitor monitor, ImmutableConfigurationSection s, string key )
        {
            return ReadStringArray( monitor, s.TryGetSection( key ) );
        }

        /// <summary>
        /// Helper that reads a string array from a string value, a comma separated string, or children
        /// sections (with string value or comma separated string) that must have integer keys ("0", "1",...).
        /// Returns null on error (and the error is logged).
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="section">The section.</param>
        /// <returns>The string array (empty if the section is null) or null on error.</returns>
        public static string[]? ReadStringArray( IActivityMonitor monitor, ImmutableConfigurationSection? section )
        {
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

        internal static bool ReadNames( IActivityMonitor monitor,
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
            return ReadNamesWithoutFullName( monitor, s, out domainName, out partyName, out environmentName, defaultDomainName, defaultPartyName, defaultEnvironmentName );

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
                    success &= !ReadName( monitor, s, NameKind.Env, out e, defaultEnvironmentName );
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

        internal static bool ReadNamesWithoutFullName( IActivityMonitor monitor,
                                                       ImmutableConfigurationSection s,
                                                       out string domainName,
                                                       out string partyName,
                                                       out string environmentName,
                                                       string? defaultDomainName,
                                                       string? defaultPartyName,
                                                       string? defaultEnvironmentName )
        {
            // No shortcut operators here to collect all the errors.
            return ReadName( monitor, s, NameKind.Domain, out domainName, defaultDomainName )
                           & ReadName( monitor, s, NameKind.Party, out partyName, defaultPartyName )
                           & ReadName( monitor, s, NameKind.Env, out environmentName, defaultEnvironmentName );
        }

        internal static bool ReadName( IActivityMonitor monitor, ImmutableConfigurationSection s, NameKind kind, out string name, string? defaultName )
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

        internal enum NameKind
        {
            Domain,
            Party,
            Env
        }

        static readonly string[] _names = new[] { "DomainName", "Name", "EnvironmentName" };

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

        /// <summary>
        /// For <see cref="NameKind.Party"/>, the '$' pre
        /// </summary>
        /// <param name="monitor"></param>
        /// <param name="configuration"></param>
        /// <param name="propertyName"></param>
        /// <param name="isRequired"></param>
        /// <param name="defaultValue"></param>
        /// <param name="value"></param>
        /// <param name="kind"></param>
        /// <returns></returns>
        internal static bool GetName( IActivityMonitor monitor,
                                      IConfigurationSection configuration,
                                      string propertyName,
                                      bool isRequired,
                                      string? defaultValue,
                                      [NotNullWhen( true )] out string? value,
                                      NameKind kind )
        {
            value = configuration[propertyName];
            if( !ValidateName( monitor, configuration, propertyName, ref value, isRequired, kind ) )
            {
                return false;
            }
            // Validates the default value if any.
            if( value == null && defaultValue != null )
            {
                if( !ValidateName( monitor, configuration, propertyName, ref defaultValue, true, kind ) ) return false;
                value = defaultValue;
            }
            Debug.Assert( value != null );
            return true;
        }

        static bool ValidateName( IActivityMonitor monitor,
                                  IConfigurationSection configuration,
                                  string propertyName,
                                  ref string? value,
                                  bool isRequired,
                                  NameKind kind )
        {
            if( string.IsNullOrWhiteSpace( value ) )
            {
                if( isRequired )
                {
                    monitor.Error( $"Configuration '{configuration.Path}:{propertyName}' is required and {_nameSyntaxes[(int)kind]}" );
                    return false;
                }
                value = null;
                return true;
            }
            bool isValid = kind switch
            {
                NameKind.Domain => CoreApplicationIdentity.IsValidDomainName( value ),
                NameKind.Party => CoreApplicationIdentity.IsValidPartyName( value ),
                NameKind.Env => CoreApplicationIdentity.IsValidEnvironmentName( value ),
                _ => Throw.NotSupportedException<bool>()
            };
            if( !isValid )
            {
                monitor.Error( $"Configuration '{configuration.Path}:{propertyName}' = '{value}' {_nameSyntaxes[(int)kind]}." );
                return false;
            }
            return true;
        }
    }
}
