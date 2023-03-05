using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;

namespace CK.AppIdentity
{
    /// <summary>
    /// Configuration that defines the identity of an application.
    /// This is designed to be available as a singleton service in the DI container (the package CK.AppIdentity.Configuration does that).
    /// </summary>
    public sealed class AppIdentityConfiguration
    {
        AppIdentityConfiguration( LockedConfigurationSection configuration,
                                  string domainName,
                                  string environmentName,
                                  LocalPartyConfiguration local,
                                  RemotePartyConfiguration[] remotes )
        {
            Configuration = configuration;
            DomainName = domainName;
            EnvironmentName = environmentName;
            Local = local;
            Remotes = remotes;
        }

        /// <summary>
        /// Tries to create an <see cref="AppIdentityConfiguration"/> instance from a <see cref="IConfigurationSection"/>
        /// and the <see cref="IHostEnvironment"/> for the defaults <see cref="IHostEnvironment.ApplicationName"/>
        /// and <see cref="IHostEnvironment.EnvironmentName"/>.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="hostEnvironment">The hosting environment from which defaults local and environment names are used.</param>
        /// <param name="configuration">The configuration section (typically named "CK-AppIdentity").</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static AppIdentityConfiguration? Create( IActivityMonitor monitor, IHostEnvironment hostEnvironment, IConfigurationSection configuration )
        {
            using var gLog = monitor.OpenInfo( "Creating root AppIdentityConfiguration service." );
            var locked = configuration as LockedConfigurationSection ?? new LockedConfigurationSection( configuration );
            bool success = GetName( monitor, locked, "DomainName", false, "LocalDev", out var domainName );
            if( !GetName( monitor, locked, "EnvironmentName", false, hostEnvironment.EnvironmentName, out var environmentName ) ) success = false;

            var local = LocalPartyConfiguration.Create( monitor, locked.GetSection( "Local" ), hostEnvironment.ApplicationName );
            if( local == null ) success = false;

            var c = CreateRemotes( monitor, locked, domainName, environmentName, local, allowTenantService: true );
            if( c == null ) monitor.CloseGroup( "Failed." );
            return c;
        }

        public static AppIdentityConfiguration? CreateTenant( IActivityMonitor monitor,
                                                              string remoteName,
                                                              string remoteEnvironmentName,
                                                              LockedConfigurationSection configuration )
        {
            using var gLog = monitor.OpenInfo( $"Creating tenant AppIdentityConfiguration for '{remoteName}/{remoteEnvironmentName}'." );
            var local = new LocalPartyConfiguration( configuration.GetSection( "Local" ), remoteName );
            var c = CreateRemotes( monitor, configuration, remoteName, remoteEnvironmentName, local, allowTenantService: false );
            if( c == null ) monitor.CloseGroup( "Failed." );
            return c;
        }

        private static AppIdentityConfiguration? CreateRemotes( IActivityMonitor monitor,
                                                                LockedConfigurationSection locked,
                                                                string? domainName,
                                                                string? environmentName,
                                                                LocalPartyConfiguration? local,
                                                                bool allowTenantService )
        {
            bool success = domainName != null && environmentName!= null && local != null;
            var remotes = new List<RemotePartyConfiguration>();
            foreach( var c in locked.GetSection( "Remotes" ).GetChildren() )
            {
                var r = RemotePartyConfiguration.Create( monitor, c, domainName!, environmentName!, allowTenantService );
                if( r == null ) success = false;
                else
                {
                    if( local != null && r.Name.Equals( local.Name, StringComparison.OrdinalIgnoreCase ) )
                    {
                        monitor.Error( $"Invalid remote party name '{r.Name}': it is this local name." );
                        success = false;
                    }
                    else if( remotes.Any( x => x.Name.Equals( r.Name, StringComparison.OrdinalIgnoreCase ) ) )
                    {
                        monitor.Error( $"Duplicate remote party name '{r.Name}': remote party name must be unique." );
                        success = false;
                    }
                    if( success ) remotes.Add( r );
                }
            }
            return success
                    ? new AppIdentityConfiguration( locked, domainName!, environmentName!, local!, remotes.ToArray() )
                    : null;
        }

        /// <summary>
        /// Gets the "CK-AppIdentity" configuration section.
        /// </summary>
        public LockedConfigurationSection Configuration { get; }

        /// <summary>
        /// Gets the name of the domain to which this application belongs.
        /// It cannot be null or empty and defaults to "LocalDev". This reserved name
        /// must prevent any logs to be sent to any collector that is not on the machine
        /// that runs this application (this is typically used on developer's machine).
        /// <para>
        /// It must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </para>
        /// </summary>
        public string DomainName { get; }

        /// <summary>
        /// Gets the name of the environment. Defaults to "Development".
        /// <para>
        /// It must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </para>
        /// </summary>
        public string EnvironmentName { get; }

        /// <summary>
        /// Gets the this configured local identity (this holds the <see cref="LocalPartyConfiguration.Name"/> of this application).
        /// </summary>
        public LocalPartyConfiguration Local { get; }

        /// <summary>
        /// Gets the set of the configured remotes.
        /// </summary>
        public IReadOnlyCollection<RemotePartyConfiguration> Remotes { get; }

        const string _nameSuffix = " must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters and must not start with a digit nor a '_'.";

        internal static bool GetName( IActivityMonitor monitor,
                                      IConfigurationSection configuration,
                                      string propertyName,
                                      bool isRequired,
                                      string? defaultValue,
                                      out string? value )
        {
            value = configuration[propertyName];
            if( !ValidateName( monitor, propertyName, ref value, isRequired ) ) return false;
            if( value == null && defaultValue != null )
            {
                monitor.Info( $"Undefined configuration property '{configuration.Path}:{propertyName}'. Using default value '{defaultValue}'." );
                value = defaultValue;
            }
            return true;
        }

        /// <summary>
        /// Common validator function for names.
        /// </summary>
        /// <param name="monitor">The monitor.</param>
        /// <param name="propertyName">The property name.</param>
        /// <param name="value">The value.</param>
        /// <param name="isRequired">Whether it is required or can be let to null.</param>
        /// <returns>True on success, false otherwise.</returns>
        public static bool ValidateName( IActivityMonitor monitor, string propertyName, ref string? value, bool isRequired )
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
            if( value.Any( c => !IsValidNameChar( c ) ) || Char.IsDigit( value[0] ) || value[0] == '_' )
            {
                monitor.Error( $"{propertyName}{_nameSuffix} {propertyName} = '{value}'." );
                return false;
            }
            return true;
        }

        static bool IsValidNameChar( char c )
        {
            return (c is >= 'a' and <= 'z') || (c is >= 'A' and <= 'Z') || (c is >= '0' and <= '9') || c == '_';
        }
    }
}
