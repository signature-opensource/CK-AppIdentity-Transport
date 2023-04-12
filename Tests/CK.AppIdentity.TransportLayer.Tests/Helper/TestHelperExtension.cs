using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Diagnostics;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.TransportLayer.Tests
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
        public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                      Action<MutableConfigurationSection> configuration,
                                                                                      Action<ServiceCollection>? configureServices = null )
        {
            var c = ApplicationIdentityConfiguration.Create( TestHelper.Monitor, configuration );
            Debug.Assert( c != null );
            return CreateApplicationServiceAsync( @this, c, configureServices );
        }

        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from its configuration.
        /// It must be disposed once done with it to stop its micro agent.
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="c">The configuration.</param>
        /// <returns>The started service.</returns>
        public static async Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                            ApplicationIdentityConfiguration c,
                                                                                            Action<ServiceCollection>? configureServices = null )
        {
            var serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<ApplicationIdentityService>();
            serviceBuilder.AddSingleton<MessageProtocolDirectoryService>();
            serviceBuilder.AddSingleton<TransportFeatureDriver>();
            configureServices?.Invoke( serviceBuilder );
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<ApplicationIdentityService>();
            // This is done by host. We wait for the FeatureBuildersInitialization task.
            _ = ((IHostedService)s).StartAsync( default );

            await s.FeatureBuildersInitialization;
            return s;
        }
    }
}
