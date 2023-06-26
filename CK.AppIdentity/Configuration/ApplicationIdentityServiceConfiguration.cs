using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

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
    public sealed class ApplicationIdentityServiceConfiguration : ApplicationIdentityPartyConfiguration
    {
        readonly ApplicationIdentityObjectConfiguration[] _remotes;
        readonly NormalizedPath _storeRootPath;
        static NormalizedPath _defaultStoreRootPath;
        static readonly object _defaultStoreRootPathLock = new object();

        ApplicationIdentityServiceConfiguration( ImmutableConfigurationSection configuration,
                                                 string domainName,
                                                 NormalizedPath fullName,
                                                 string store,
                                                 ApplicationIdentityObjectConfiguration[] remotes,
                                                 ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, ref inhProps )
        {
            _storeRootPath = store;
            _remotes = remotes;
        }

        /// <summary>
        /// Gets the remote configurations that can be:
        /// <list type="bullet">
        ///   <item><see cref="RemotePartyConfiguration"/> for a remote party.</item>
        ///   <item><see cref="PartyGroupConfiguration"/> for group of remotes (composite remote).</item>
        ///   <item>Base <see cref="ApplicationIdentityObjectConfiguration"/> for external remotes (when DomainName is <see cref="CoreApplicationIdentity.DefaultDomainName"/>).</item>
        /// </list>
        /// </summary>
        public IReadOnlyCollection<ApplicationIdentityObjectConfiguration> Remotes => _remotes;

        /// <summary>
        /// Gets the file storage root path. Defaults to <see cref="DefaultStoreRootPath"/>.
        /// <para>
        /// This folder is de facto shared by all applications (parties) that use CK.AppIdentity and run on this computer.
        /// Such installed parties can use <see cref="ApplicationIdentityService.PrivateStorePath"/> folder to store any application 
        /// specific data. All installed parties can use <see cref="IParty.SharedStorePath"/> to store and share data related to parties.
        /// </para>
        /// </summary>
        public NormalizedPath StoreRootPath => _storeRootPath;

        /// <summary>
        /// Gets or sets the default store path that is by default "<see cref="Environment.SpecialFolder.LocalApplicationData"/>/CK-AppIdentity".
        /// <para>
        /// This is primarily intended for tests and must be set prior to any access to this property: once this property is accessed or set,
        /// its value is settled. 
        /// </para>
        /// </summary>
        public static NormalizedPath DefaultStoreRootPath
        {
            get
            {
                var p = _defaultStoreRootPath;
                if( p.IsEmptyPath )
                {
                    lock( _defaultStoreRootPathLock )
                    {
                        p = _defaultStoreRootPath;
                        if( p.IsEmptyPath )
                        {
                            p = Environment.GetFolderPath( Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify );
                            p = Path.Combine( p, "CK-AppIdentity" );
                        }
                    }
                    _defaultStoreRootPath = p;
                }
                return p;
            }
            set
            {
                var p = _defaultStoreRootPath;
                if( p.IsEmptyPath )
                {
                    lock( _defaultStoreRootPathLock )
                    {
                        p = _defaultStoreRootPath;
                        if( p.IsEmptyPath ) p = value;
                    }
                    _defaultStoreRootPath = p;
                }
            }
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a <see cref="IConfigurationSection"/>
        /// and the <see cref="IHostEnvironment"/>: the <see cref="IHostEnvironment.ApplicationName"/> is the default party name
        /// and <see cref="IHostEnvironment.EnvironmentName"/> is the default environment name.
        /// <para>
        /// If the configuration doesn't specify the "DomainName" (or defines the "FullName" of the party), "Default" domain name
        /// is used.
        /// </para>
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="hostEnvironment">The hosting environment from which defaults party and environment names are used.</param>
        /// <param name="configuration">The configuration section (typically named "CK-AppIdentity").</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
                                                                       IHostEnvironment hostEnvironment,
                                                                       IConfigurationSection configuration )
        {
            var env = hostEnvironment.EnvironmentName;
            if( string.IsNullOrWhiteSpace( env ) )
            {
                env = CoreApplicationIdentity.DefaultEnvironmentName;
            }
            else if( env[0] != '#' )
            {
                env = '#' + env;
            }
            if( env.Length > CoreApplicationIdentity.EnvironmentNameMaxLength )
            {
                env = env.Substring( 0, CoreApplicationIdentity.EnvironmentNameMaxLength );
            }
            return Create( monitor, configuration, "Default", hostEnvironment.ApplicationName, env );
        }

        /// <summary>
        /// Tries to create an <see cref="ApplicationIdentityConfiguration"/> instance from a "CK-AppIdentity" <see cref="MutableConfigurationSection"/>
        /// that is setup by a callback. At least "DomainName" and "PartyName" (or FullName") configuration must be set ("EnvironmentName" defaults
        /// to "#Development").
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
        /// <param name="defaultDomainName">A valid domain name to use if the <paramref name="configuration"/> doesn't specify "DomainName".</param>
        /// <param name="defaultPartyName">A valid party name to use if the <paramref name="configuration"/> doesn't specify "PartyName".</param>
        /// <param name="defaultEnvironmentName">A valid environment name to use if the <paramref name="configuration"/> doesn't specify it.</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
                                                                       IConfigurationSection configuration,
                                                                       string? defaultDomainName = null,
                                                                       string? defaultPartyName = null,
                                                                       string defaultEnvironmentName = CoreApplicationIdentity.DefaultEnvironmentName )
        {
            Throw.CheckNotNullArgument( defaultEnvironmentName );
            using var gLog = monitor.OpenInfo( "Creating root AppIdentityConfiguration service." );
            var root = configuration as ImmutableConfigurationSection ?? new ImmutableConfigurationSection( configuration );

            bool success = ReadNames( monitor, root, out var domainName, out var partyName, out var environmentName, defaultDomainName, defaultPartyName, defaultEnvironmentName );

            success &= InheritedConfigurationProps.TryCreate( monitor, root, out var inheritedProps );

            if( ReferenceEquals( domainName, "External" ) )
            {
                Debug.Assert( CoreApplicationIdentity.DefaultDomainName == "Undefined" );
                monitor.Error( $"Root domain name cannot be \"External\" or \"Undefined\". This name denotes an external system." );
                success = false;
            }

            // Always try to create the parties even if success is already false: this enables
            // configuration errors to be fixed at once.
            var fullNameIndex = new Dictionary<string, ImmutableConfigurationSection>( StringComparer.OrdinalIgnoreCase );
            var parties = CreateParties( monitor, root.GetSection( "Parties" ), domainName, environmentName, ref inheritedProps, fullNameIndex );
            success &= parties != null;

            var store = HandleStorePath( monitor, configuration );
            success &= store != null;

            if( !success )
            {
                monitor.CloseGroup( "Failed." );
                return null;
            }
            var fullName = partyName[0] == '$' ? $"{domainName}/{partyName}/{environmentName}" : $"{domainName}/${partyName}/{environmentName}";
            return new ApplicationIdentityServiceConfiguration( root, domainName, fullName, store!, parties!, ref inheritedProps );

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
                    store = DefaultStoreRootPath;
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

        static ApplicationIdentityObjectConfiguration[]? CreateParties( IActivityMonitor monitor,
                                                                        ImmutableConfigurationSection configuration,
                                                                        string domainName,
                                                                        string environmentName,
                                                                        ref InheritedConfigurationProps domainProps,
                                                                        Dictionary<string, ImmutableConfigurationSection> fullNameIndex )
        {
            Debug.Assert( configuration.Key == "Parties" );
            bool success = domainProps.IsValid;
            var parties = new List<ApplicationIdentityObjectConfiguration>();
            foreach( var c in configuration.GetChildren() )
            {
                var r = CreateParty( monitor, c, domainName, environmentName, ref domainProps, fullNameIndex );
                if( r == null ) success = false;
                else if( success ) parties.Add( r );
            }
            return success ? parties.ToArray() : null;

        }

        internal static ApplicationIdentityObjectConfiguration? CreateParty( IActivityMonitor monitor,
                                                                             ImmutableConfigurationSection configuration,
                                                                             string? appDomainName,
                                                                             string? appEnvironmentName,
                                                                             ref InheritedConfigurationProps domainProps,
                                                                             Dictionary<string,ImmutableConfigurationSection> fullNameIndex )
        {
            // Handles "Parties" as the first discriminator.
            var remotesSection = configuration.GetSection( "Parties" );
            if( remotesSection.Exists() )
            {
                return HandlePartyGroup( monitor, configuration, appDomainName, appEnvironmentName, domainProps, fullNameIndex, remotesSection );
            }
            else
            {
                return HandleParty( monitor, configuration, appDomainName, appEnvironmentName, domainProps, fullNameIndex );
            }

            static PartyGroupConfiguration? HandlePartyGroup( IActivityMonitor monitor,
                                                              ImmutableConfigurationSection configuration,
                                                              string? appDomainName,
                                                              string? appEnvironmentName,
                                                              InheritedConfigurationProps domainProps,
                                                              Dictionary<string, ImmutableConfigurationSection> fullNameIndex,
                                                              ImmutableConfigurationSection remotesSection )
            {
                using var gLog = monitor.OpenInfo( $"Remote group found '{remotesSection.Path}'." );
                bool success = configuration.CheckNotExist( monitor, "FullName", "FullName cannot be used on a group (a Remote with Remotes). Only DomainName or EnvironmentName can be defined." )
                                & configuration.CheckNotExist( monitor, "PartyName", "PartyName cannot be used on a group (a Remote with Remotes). Only DomainName or EnvironmentName can be defined." )
                                & ReadName( monitor, configuration, NameKind.Domain, out var domainName, appDomainName )
                                & ReadName( monitor, configuration, NameKind.Env, out var environmentName, appEnvironmentName )
                                & InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var inhProps );
                // The "Undefined" domain name cannot be a group. 
                if( domainName == CoreApplicationIdentity.DefaultDomainName )
                {
                    monitor.Error( $"Invalid configuration '{remotesSection.Path}': '{CoreApplicationIdentity.DefaultDomainName}' cannot contain Remotes. This name denotes an external system." );
                    success = false;
                }
                var remotes = CreateParties( monitor, remotesSection, domainName, environmentName, ref inhProps, fullNameIndex );
                success &= remotes != null;

                return success
                        ? new PartyGroupConfiguration( configuration, domainName, environmentName, remotes!, ref inhProps )
                        : null;
            }

            static ApplicationIdentityPartyConfiguration? HandleParty( IActivityMonitor monitor,
                                                                       ImmutableConfigurationSection configuration,
                                                                       string? appDomainName,
                                                                       string? appEnvironmentName,
                                                                       InheritedConfigurationProps domainProps,
                                                                       Dictionary<string, ImmutableConfigurationSection> fullNameIndex )
            {
                bool success = ReadNames( monitor, configuration,
                                          out var domainName, out var partyName, out var environmentName,
                                          appDomainName, null, appEnvironmentName )
                               & InheritedConfigurationProps.TryCreate( monitor, domainProps, configuration, out var remoteProps );

                bool isLocalParty;
                NormalizedPath fullName;
                if( partyName[0] == '$' )
                {
                    fullName = $"{domainName}/{partyName}/{environmentName}";
                    isLocalParty = partyName.AsSpan( 1 ).Equals( fullName.Parts[^3], StringComparison.OrdinalIgnoreCase );
                }
                else
                {
                    fullName = $"{domainName}/${partyName}/{environmentName}";
                    isLocalParty = partyName.Equals( fullName.Parts[^3], StringComparison.OrdinalIgnoreCase );
                }
                Debug.Assert( fullNameIndex.Comparer == StringComparer.OrdinalIgnoreCase );
                if( fullNameIndex.TryGetValue( fullName, out var exists ) )
                {
                    monitor.Error( $"Duplicate party definition '{configuration.Path}': full name '{fullName}' is already defined by '{exists.Path}'." );
                    success = false;
                }
                else
                {
                    fullNameIndex.Add( fullName, configuration );
                }
                return success
                        ? isLocalParty
                            ? new LocalPartyConfiguration( configuration, domainName, fullName, ref remoteProps )
                            : new RemotePartyConfiguration( configuration, domainName, fullName, configuration["Address"], ref remoteProps )
                        : null;
            }
        }


    }
}
