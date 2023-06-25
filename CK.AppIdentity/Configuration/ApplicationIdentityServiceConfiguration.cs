using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Configuration that defines the initial identity of an application.
    /// This is designed to be available as a singleton service in the DI container (the package CK.AppIdentity.Configuration does that).
    /// <para>
    /// Configurations are immutable (any existing configuration cannot be changed) but dynamic remote parties (that can be groups of remotes)
    /// can be added and destroyed.
    /// </para>
    /// </summary>
    public sealed class ApplicationIdentityServiceConfiguration : RemoteCollectionConfiguration
    {
        readonly string _partyName;
        private readonly NormalizedPath _storeRootPath;

        ApplicationIdentityServiceConfiguration( ImmutableConfigurationSection configuration,
                                                 string domainName,
                                                 NormalizedPath fullName,
                                                 string store,
                                                 ApplicationIdentityBaseConfiguration[] remotes,
                                                 ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, remotes, ref inhProps )
        {
            Debug.Assert( CoreApplicationIdentity.TryParseFullName( fullName.Path, out var d, out var p, out var e )
                            && d == domainName && e == fullName.LastPart && p == fullName.Parts[^2] );

            _partyName = fullName.Parts[^2];
            _storeRootPath = store;
        }

        /// <summary>
        /// Gets this application party name.
        /// </summary>
        public string PartyName => _partyName;

        /// <summary>
        /// Gets the file storage root path.
        /// <para>
        /// When not configured, this defaults to "<see cref="Environment.SpecialFolder.LocalApplicationData"/>/CK-AppIdentity/":
        /// this folder is de facto shared by all applications (parties) that use CK.AppIdentity and run on this computer.
        /// Such installed parties can use <see cref="ApplicationIdentityService.PrivateStorePath"/> folder to store any application 
        /// specific data. All installed parties can use <see cref="ApplicationIdentityService.SharedStorePath"/> and <see cref="IRemote.SharedStorePath"/>
        /// to store and share data related to parties.
        /// </para>
        /// </summary>
        public NormalizedPath StoreRootPath => _storeRootPath;

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a <see cref="IConfigurationSection"/>
        /// and the <see cref="IHostEnvironment"/> for the defaults <see cref="IHostEnvironment.ApplicationName"/>
        /// and <see cref="IHostEnvironment.EnvironmentName"/>.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="hostEnvironment">The hosting environment from which defaults party and environment names are used.</param>
        /// <param name="configuration">The configuration section (typically named "CK-AppIdentity").</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
                                                                       IHostEnvironment hostEnvironment,
                                                                       IConfigurationSection configuration )
        {
            return Create( monitor, configuration, hostEnvironment.ApplicationName, hostEnvironment.EnvironmentName );
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a "CK-AppIdentity" <see cref="MutableConfigurationSection"/>
        /// that is setup by a callback. At least "DomainName" and "Name" configuration must be set ("EnvironmentName" defaults to "Development").
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="configuration">Must configure the "CK-AppIdentity" section.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
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
        /// <param name="defaultLocalName">A valid local name to use if the <paramref name="configuration"/> doesn't specify "PartyName".</param>
        /// <param name="defaultEnvironmentName">A valid environment name to use if the <paramref name="configuration"/> doesn't specify it.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
                                                                       IConfigurationSection configuration,
                                                                       string? defaultLocalName = null,
                                                                       string defaultEnvironmentName = CoreApplicationIdentity.DefaultEnvironmentName )
        {
            Throw.CheckNotNullArgument( defaultEnvironmentName );
            using var gLog = monitor.OpenInfo( "Creating root AppIdentityConfiguration service." );
            var root = configuration as ImmutableConfigurationSection ?? new ImmutableConfigurationSection( configuration );

            bool success = ReadNames( monitor, root, out var domainName, out var partyName, out var environmentName, null, defaultLocalName, defaultEnvironmentName );

            success &= InheritedConfigurationProps.TryCreate( monitor, root, out var inheritedProps );

            if( domainName == CoreApplicationIdentity.DefaultDomainName )
            {
                monitor.Error( $"Root domain name cannot be '{CoreApplicationIdentity.DefaultDomainName}'. This name denotes an external system." );
                success = false;
            }

            // Always try to create the remotes even if success is already false: this enables
            // configuration errors to be fixed at once.
            var fullNameIndex = new Dictionary<string, ImmutableConfigurationSection>( StringComparer.OrdinalIgnoreCase );
            var remotes = CreateRemotes( monitor, root.GetSection( "Remotes" ), domainName, environmentName, ref inheritedProps, fullNameIndex );
            success &= remotes != null;

            var store = HandleStorePath( monitor, configuration );
            success &= store != null;

            if( !success )
            {
                monitor.CloseGroup( "Failed." );
                return null;
            }
            var fullName = $"{domainName}/${partyName}/{environmentName}";
            return new ApplicationIdentityServiceConfiguration( root, domainName, fullName, store!, remotes!, ref inheritedProps );

            static string? HandleStorePath( IActivityMonitor monitor, IConfigurationSection configuration )
            {
                var store = configuration[nameof( StoreRootPath )]?.Trim();
                if( !string.IsNullOrEmpty( store ) )
                {
                    if( FileUtil.IndexOfInvalidPathChars( store ) >= 0 )
                    {
                        monitor.Error( $"Invalid path '{configuration.Path}:{nameof( StoreRootPath )}'. Invalid characters in '{store}'." );
                        return null;
                    }
                    if( !Path.IsPathFullyQualified( store ) )
                    {
                        monitor.Error( $"Invalid path '{configuration.Path}:{nameof( StoreRootPath )}'. '{store}' must not be relative." );
                        return null;
                    }
                }
                else
                {
                    store = Environment.GetFolderPath( Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify );
                    store = Path.Combine( store, "CK-AppIdentity" );
                }
                try
                {
                    Directory.CreateDirectory( store );
                }
                catch( Exception ex )
                {
                    monitor.Error( $"Unable to create store directory '{store}'.", ex );
                    return null;
                }
                return store;
            }
        }

        static ApplicationIdentityBaseConfiguration[]? CreateRemotes( IActivityMonitor monitor,
                                                                      ImmutableConfigurationSection configuration,
                                                                      string domainName,
                                                                      string environmentName,
                                                                      ref InheritedConfigurationProps domainProps,
                                                                      Dictionary<string, ImmutableConfigurationSection> fullNameIndex )
        {
            Debug.Assert( configuration.Key == "Remotes" );
            bool success = domainProps.IsValid;
            var remotes = new List<ApplicationIdentityBaseConfiguration>();
            foreach( var c in configuration.GetChildren() )
            {
                var r = CreateRemote( monitor, c, domainName, environmentName, ref domainProps, fullNameIndex );
                if( r == null ) success = false;
                else if( success ) remotes.Add( r );
            }
            return success ? remotes.ToArray() : null;

        }

        internal static ApplicationIdentityBaseConfiguration? CreateRemote( IActivityMonitor monitor,
                                                                            ImmutableConfigurationSection configuration,
                                                                            string? appDomainName,
                                                                            string? appEnvironmentName,
                                                                            ref InheritedConfigurationProps domainProps,
                                                                            Dictionary<string,ImmutableConfigurationSection> fullNameIndex )
        {
            // "Remotes" configuration handling.
            var remotesSection = configuration.GetSection( "Remotes" );
            bool success;
            if( remotesSection.Exists() )
            {
                using var gLog = monitor.OpenInfo( $"Remote group found '{remotesSection.Path}'." );
                success = configuration.CheckNotExist( monitor, "FullName", "FullName cannot be used on a group (a Remote with Remotes). Only DomainName or EnvironmentName can be defined." )
                            & configuration.CheckNotExist( monitor, "PartyName", "PartyName cannot be used on a group (a Remote with Remotes). Only DomainName or EnvironmentName can be defined." )
                            & ReadName( monitor, configuration, NameKind.Domain, out var domainName, appDomainName )
                            & ReadName( monitor, configuration, NameKind.Env, out var environmentName, appEnvironmentName )
                            & InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var inhProps );
                var fullName = $"{domainName}/{environmentName}";
                if( fullNameIndex.TryGetValue( fullName, out var exists ) )
                {
                    monitor.Error( $"Duplicate group definition '{configuration.Path}': full name '{fullName}' is already defined by '{exists.Path}'." );
                    success = false;
                }
                else
                {
                    fullNameIndex.Add( fullName, configuration );
                }
                // The "Undefined" domain name cannot be a domain. 
                if( domainName == CoreApplicationIdentity.DefaultDomainName )
                {
                    monitor.Error( $"Invalid configuration '{remotesSection.Path}': '{CoreApplicationIdentity.DefaultDomainName}' cannot host a domain. This name denotes an external system." );
                    success = false;
                }
                var remotes = CreateRemotes( monitor, remotesSection, domainName, environmentName, ref inhProps, fullNameIndex );
                success &= remotes != null;

                return success
                        ? new RemoteCollectionConfiguration( configuration, domainName, fullName, remotes!, ref inhProps )
                        : null;
            }
            else
            {
                success = ReadNames( monitor, configuration,
                                     out var domainName, out var name, out var environmentName,
                                     appDomainName, null, appEnvironmentName )
                          & InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var remoteProps );

                var fullName = $"{domainName}/${name}/{environmentName}";
                if( fullNameIndex.TryGetValue( fullName, out var exists ) )
                {
                    monitor.Error( $"Duplicate remote party definition '{configuration.Path}': full name '{fullName}' is already defined by '{exists.Path}'." );
                    success = false;
                }
                else
                {
                    fullNameIndex.Add( fullName, configuration );
                }
                return success
                        ? new RemotePartyConfiguration( configuration, domainName, fullName, configuration["Address"], ref remoteProps )
                        : null;
            }

        }


    }
}
