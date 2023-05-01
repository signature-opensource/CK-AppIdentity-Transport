using CK.Core;
using CK.Cris;
using CK.Setup;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using CK.AppIdentity.TransportLayer;
using FluentAssertions.Common;

namespace CK.AppIdentity.Cris.Tests
{
    static class TestHelperExtension
    {
        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from a configuration builder.
        /// It must be disposed once done with it to stop its micro agent.
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="configuration">The configuration.</param>
        /// <returns>The started service.</returns>
        public static Task<ApplicationIdentityWithServices> CreateApplicationServiceAsync( this IStObjEngineTestHelper @this,
                                                                                           Action<MutableConfigurationSection> configuration,
                                                                                           Action<StObjContextRoot.ServiceRegister>? configureServices = null,
                                                                                           params Type[] types )
        {
            var c = ApplicationIdentityConfiguration.Create( @this.Monitor, configuration );
            Debug.Assert( c != null );
            return CreateApplicationServiceAsync( @this, c, configureServices, types );
        }

        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from its configuration.
        /// It must be disposed once done with it to stop its micro agent.
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="c">The configuration.</param>
        /// <param name="configureServices">Optional services configuration hook.</param>
        /// <param name="types">Types for <see cref="StObjCollector.RegisterTypes(IReadOnlyCollection{Type})"/></param>
        /// <returns>The started service.</returns>
        public static async Task<ApplicationIdentityWithServices> CreateApplicationServiceAsync( this IStObjEngineTestHelper @this,
                                                                                                 ApplicationIdentityConfiguration c,
                                                                                                 Action<StObjContextRoot.ServiceRegister>? configureServices = null,
                                                                                                 params Type[] types )
        {
            StObjCollector collector = @this.CreateStObjCollector();
            collector.SetAutoServiceKind( typeof( ApplicationIdentityConfiguration ), AutoServiceKind.IsSingleton );
            collector.RegisterTypes( new Type[]
            {
                // Cris bas types.
                typeof( CommandDirectory ),
                typeof( RawCrisValidator ),
                typeof( RawCrisExecutor ),
                typeof( ICrisResultError ),
                typeof( CK.Cris.AmbientValues.IAmbientValues ),
                // Triggers code generation for Json serialization.
                typeof( PocoJsonSerializer ),
                // The ApplicationIdentityConfiguration is declared as a AutoServiceKind.IsSingleton above.
                typeof( ApplicationIdentityService ),
                typeof( MessageProtocolDirectoryService ),
                typeof( TransportFeatureDriver ),
                typeof( CrisChannelFeatureDriver ),
                typeof( CrisChannelExecutor ),
                typeof( TcpSocketTransportTypeService ),
                // Authentication stuff.
                typeof( AuthenticationInfoTokenService ),
                typeof( Auth.StdAuthenticationTypeSystem ),
            } );
            collector.RegisterTypes( types );

            var services = @this.CreateAutomaticServices( collector, configureServices: services =>
            {
                services.Services.AddSingleton( c );
                configureServices?.Invoke( services );
            } ).Services;

            var s = services.GetRequiredService<ApplicationIdentityService>();
            // This is done by host. We wait for the FeatureBuildersInitialization task.
            _ = ((IHostedService)s).StartAsync( default );
            await s.InitializationTask.ConfigureAwait( false );
            return new ApplicationIdentityWithServices( s, services );
        }
    }
}
