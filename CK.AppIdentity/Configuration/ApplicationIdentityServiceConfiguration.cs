using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks.Sources;

namespace CK.AppIdentity
{
    /// <summary>
    /// Configuration that defines the initial identity of an application.
    /// This is designed to be available as a singleton service in the DI container (the package CK.AppIdentity.Configuration does that).
    /// <para>
    /// Configurations are immutable (any existing configuration cannot be changed) but dynamic remote or tenant domain parties can be added
    /// and destroyed.
    /// </para>
    /// </summary>
    public sealed class ApplicationIdentityServiceConfiguration : ApplicationIdentityPartyConfiguration
    {
        readonly List<RemotePartyConfiguration> _remotes;
        readonly List<TenantDomainPartyConfiguration> _tenants;
        readonly NormalizedPath _storeRootPath;
        static NormalizedPath _defaultStoreRootPath;
        static readonly object _defaultStoreRootPathLock = new object();

        ApplicationIdentityServiceConfiguration( ImmutableConfigurationSection configuration,
                                                 string domainName,
                                                 NormalizedPath fullName,
                                                 string store,
                                                 ref ProcessedConfiguration? parties,
                                                 ref InheritedConfigurationProps inhProps )
            : base( configuration, domainName, fullName, ref inhProps )
        {
            Debug.Assert( parties.HasValue );
            _storeRootPath = store;
            _remotes = parties.Value.Remotes;
            _tenants = parties.Value.Tenants;
        }

        /// <summary>
        /// Gets the remote parties if any.
        /// </summary>
        public IReadOnlyCollection<RemotePartyConfiguration> Remotes => _remotes;

        /// <summary>
        /// Gets the tenant domains if any.
        /// </summary>
        public IReadOnlyCollection<TenantDomainPartyConfiguration> TenantDomains => _tenants;

        /// <summary>
        /// Gets the file storage root path. Defaults to <see cref="DefaultStoreRootPath"/>.
        /// <para>
        /// This folder is de facto shared by all applications (parties) that use CK.AppIdentity and run on this computer.
        /// Such installed parties can use <see cref="ApplicationIdentityService.PrivateStorePath"/> folder to store any application 
        /// specific data. All installed parties can use <see cref="IOwnedParty.SharedStorePath"/> to store and share data related to parties.
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
        /// <param name="defaultEnvironmentName">A valid environment name to use if the <paramref name="configuration"/> doesn't specify "EnvironmentName".</param>
        /// <returns>A valid instance on success, null on configuration error.</returns>
        public static ApplicationIdentityServiceConfiguration? Create( IActivityMonitor monitor,
                                                                       IConfigurationSection configuration,
                                                                       string? defaultDomainName = null,
                                                                       string? defaultPartyName = null,
                                                                       string defaultEnvironmentName = CoreApplicationIdentity.DefaultEnvironmentName )
        {
            Throw.CheckNotNullArgument( defaultEnvironmentName );
            using var gLog = monitor.OpenInfo( "Creating root ApplicationIdentityServiceConfiguration service." );
            var root = configuration as ImmutableConfigurationSection ?? new ImmutableConfigurationSection( configuration );

            bool success = ReadNames( monitor, root,
                                      out var domainName, out var partyName, out var environmentName,
                                      defaultDomainName, defaultPartyName, defaultEnvironmentName )
                           & InheritedConfigurationProps.TryCreate( monitor, root, out var props );

            if( ReferenceEquals( domainName, "External" ) )
            {
                Debug.Assert( CoreApplicationIdentity.DefaultDomainName == "Undefined" );
                monitor.Error( $"Root domain name cannot be \"External\" or \"Undefined\". This name denotes an external system." );
                success = false;
            }

            // Always try to create the parties even if success is already false: this enables
            // configuration errors to be fixed at once.
            var fullNameIndex = new Dictionary<string, ImmutableConfigurationSection>( StringComparer.OrdinalIgnoreCase );
            var parties = CreateParties( monitor, root.GetSection( "Parties" ), domainName, environmentName, ref props, fullNameIndex );
            success &= parties.HasValue;

            var store = HandleStorePath( monitor, configuration );
            success &= store != null;

            if( !success )
            {
                monitor.CloseGroup( "Failed." );
                return null;
            }
            var fullName = partyName[0] == '$' ? $"{domainName}/{partyName}/{environmentName}" : $"{domainName}/${partyName}/{environmentName}";
            return new ApplicationIdentityServiceConfiguration( root, domainName, fullName, store!, ref parties, ref props );

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

        static ProcessedConfiguration? CreateParties( IActivityMonitor monitor,
                                                      ImmutableConfigurationSection configuration,
                                                      string domainName,
                                                      string environmentName,
                                                      ref InheritedConfigurationProps props,
                                                      Dictionary<string, ImmutableConfigurationSection> fullNameIndex )
        {
            Debug.Assert( configuration.Key == "Parties" );
            bool success = props.IsValid;
            var parties = new ProcessedConfiguration( new List<TenantDomainPartyConfiguration>(), new List<RemotePartyConfiguration>() );
            foreach( var c in configuration.GetChildren() )
            {
                success &= ReadParties( monitor, c, domainName, environmentName, ref props, ref parties, fullNameIndex );
            }
            return success ? parties : null;
        }

        internal static bool ReadParties( IActivityMonitor monitor,
                                          ImmutableConfigurationSection configuration,
                                          string inhDomainName,
                                          string inhEnvironmentName,
                                          ref InheritedConfigurationProps inhProps,
                                          ref ProcessedConfiguration partyCollector,
                                          Dictionary<string, ImmutableConfigurationSection> fullNameIndex )
        {
            var partiesSection = configuration.GetSection( "Parties" );
            bool nameSuccess = ReadNames(monitor, configuration,
                                          out var domainName, out var partyName, out var environmentName,
                                          inhDomainName, "", inhEnvironmentName );
            // Always try to propagate the inherited props.
            bool success = nameSuccess & InheritedConfigurationProps.TryCreate( monitor, inhProps, configuration, out var props );
            // If a PartyName is not defined, it is a pure group. We handle it recursively, handling inherited names and properties.
            if( partyName.Length == 0 )
            {
                using var gLog = monitor.OpenInfo( $"Party group found '{partiesSection.Path}'." );
                int count = partyCollector.Count;
                foreach( var c in configuration.GetChildren() )
                {
                    success &= ReadParties( monitor, c, domainName, environmentName, ref props, ref partyCollector, fullNameIndex );
                }
                if( success ) monitor.CloseGroup( $"Found {partyCollector.Count - count} parties." );
                else monitor.CloseGroup( "Failed." );
                return success;
            }
            // It is a Party: a TenantDomainPartyConfiguration or a RemotePartyConfiguration.
            bool isDomain;
            NormalizedPath fullName;
            string? address = configuration["Address"];
            if( partyName[0] == '$' )
            {
                fullName = $"{domainName}/{partyName}/{environmentName}";
                isDomain = address == null && partyName.AsSpan( 1 ).Equals( fullName.Parts[^3], StringComparison.OrdinalIgnoreCase );
            }
            else
            {
                fullName = $"{domainName}/${partyName}/{environmentName}";
                isDomain = address == null && partyName.Equals( fullName.Parts[^3], StringComparison.OrdinalIgnoreCase );
            }
            // Check full name unicity in this whole configuration only if the names have been successfully read.
            Debug.Assert( fullNameIndex.Comparer == StringComparer.OrdinalIgnoreCase );
            if( nameSuccess )
            {
                if (fullNameIndex.TryGetValue(fullName, out var exists))
                {
                    monitor.Error($"Duplicate party definition '{configuration.Path}': '{fullName}' is already defined by '{exists.Path}'.");
                    success = false;
                }
                else
                {
                    fullNameIndex.Add(fullName, configuration);
                }
            }
            if( isDomain )
            {
                using var gLog = monitor.OpenInfo( $"Found domain definition '{fullName}'." );
                var parties = CreateParties( monitor, partiesSection, domainName, environmentName, ref props, fullNameIndex );
                if( parties.HasValue )
                {
                    // Lifts the tenants found below.
                    partyCollector.Tenants.AddRange( parties.Value.Tenants );
                    // Adds the found tenant if there's no issue with its names.
                    if( nameSuccess )
                    {
                        partyCollector.Tenants.Add( new TenantDomainPartyConfiguration( configuration, domainName, fullName, parties.Value.Remotes, ref props ) );
                    }
                }
                else
                {
                    success = false;
                }
            }
            else
            {
                if( success )
                {
                    var p = new RemotePartyConfiguration( configuration, domainName, fullName, address, ref props );
                    partyCollector.Remotes.Add( p );
                    monitor.Info( $"Fond '{fullName}' {(p.IsExternalParty ? "external " : "")} remote party." );
                }
            }
            return success;
        }
    }
}
