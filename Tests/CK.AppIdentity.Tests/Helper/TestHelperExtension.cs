using CK.Core;
using CK.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
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
        public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this, Action<MutableConfigurationSection> configuration )
        {
            var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration );
            Throw.DebugAssert( c != null );
            return CreateApplicationServiceAsync( @this, c );
        }

        /// <summary>
        /// Creates a <see cref="ApplicationIdentityService"/> from its configuration.
        /// It must be disposed once done with it to stop its micro agent.
        /// </summary>
        /// <param name="this">This test helper.</param>
        /// <param name="c">The configuration.</param>
        /// <returns>The started service.</returns>
        public static async Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this, ApplicationIdentityServiceConfiguration c )
        {
            var serviceBuilder = new ServiceCollection();
            serviceBuilder.AddSingleton( c );
            serviceBuilder.AddSingleton<ApplicationIdentityService>();
            var services = serviceBuilder.BuildServiceProvider();

            var s = services.GetRequiredService<ApplicationIdentityService>();
            // This is done by host. We wait for the FeatureBuildersInitialization task.
            _ = ((IHostedService)s).StartAsync( default );

            await s.InitializationTask;
            return s;
        }
    }
}
