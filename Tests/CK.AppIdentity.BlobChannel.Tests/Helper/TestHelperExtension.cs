using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.BlobChannel.Tests
{

    static class TestHelperExtension
    {
        public static NormalizedPath TestStoreFolder = TestHelper.TestProjectFolder.AppendPart( "TestStore" );

        public static NormalizedPath GetCleanTestStoreFolder( this IBasicTestHelper helper )
        {
            return helper.CleanupFolder( TestStoreFolder );
        }

        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from a configuration builder.
        /// It must be disposed once done with it to stop its micro agent.
        /// <para>
        /// See <see cref="CreateApplicationServiceAsync(IBasicTestHelper, ApplicationIdentityServiceConfiguration, Action{ServiceCollection}?)"/>.
        /// </para>
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="configuration">The configuration.</param>
        /// <param name="configureServices">Optional services configurator.</param>
        /// <returns>The started service.</returns>
        public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                      Action<MutableConfigurationSection> configuration,
                                                                                      Action<ServiceCollection>? configureServices = null )
        {
            var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration );
            Throw.DebugAssert( c != null );
            return CreateApplicationServiceAsync( @this, c, configureServices );
        }

        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from its configuration.
        /// It must be disposed once done with it to stop its micro agent.
        /// <para>
        /// Services are configured by default with the <see cref="ApplicationIdentityServiceConfiguration"/>,
        /// MessageProtocolDirectoryService, <see cref="FakeProtector"/>, KeyManagementFeatureDriver,
        /// TransportFeatureDriver, TcpSocketTransportTypeService and the BlobChannelFeatureDriver.
        /// </para>
        /// <para>
        /// The <see cref="ApplicationIdentityService"/> is started manually (IHostedService) because we don't have
        /// Automatic DI here, and its <see cref="ApplicationIdentityService.InitializationTask"/> is awaited:
        /// the ApplicationIdentityService is running.
        /// </para>
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="c">The configuration.</param>
        /// <param name="configureServices">Optional services configurator.</param>
        /// <returns>The started service.</returns>
        public static async Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                            ApplicationIdentityServiceConfiguration c,
                                                                                            Action<ServiceCollection>? configureServices = null )
        {
            var serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<ApplicationIdentityService>();
            serviceBuilder.AddSingleton<MessageProtocolDirectoryService>();

            serviceBuilder.AddSingleton<IDataProtectionProvider>( sp => FakeProtector.Fake );

            // Adds the TransportFeatureDriver before the KeyManagementFeatureDriver to test
            // the existence of the dependency from TransportFeatureDriver to KeyManagementFeatureDriver.
            // (Without the - unused - constructor parameter, registering services in this order fails.)
            serviceBuilder.AddSingleton<TransportFeatureDriver>();
            serviceBuilder.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<TransportFeatureDriver>() );

            serviceBuilder.AddSingleton<KeyManagementFeatureDriver>();
            serviceBuilder.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<KeyManagementFeatureDriver>() );

            serviceBuilder.AddSingleton<BlobChannelFeatureDriver>();
            serviceBuilder.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<BlobChannelFeatureDriver>() );

            serviceBuilder.AddSingleton<TcpSocketTransportTypeService>();
            serviceBuilder.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<TcpSocketTransportTypeService>() );

            configureServices?.Invoke( serviceBuilder );
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<ApplicationIdentityService>();
            // This is done by host. We wait for the FeatureBuildersInitialization task.
            _ = ((IHostedService)s).StartAsync( default );

            await s.InitializationTask.ConfigureAwait( false );
            return s;
        }
    }
}
