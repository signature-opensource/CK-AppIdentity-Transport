using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Testing;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity;

/// <summary>
/// Extends the <see cref="IMonitorTestHelper"/>.
/// </summary>
public static class TestHelperExtensions
{
    /// <summary>
    /// Creates a started service from a configuration builder. Dispose it to stop its micro agent.
    /// <para>
    /// Only <c>tcp:</c> is registered here. Any another transport — a real one
    /// like <c>mtls:</c>, or a fault-injecting one — must be added through <c>configureServices</c>, which runs
    /// last so it can also replace what this registers: the system clock, in particular, whose fake is
    /// how most timing tests stay fast.
    /// </para>
    /// <para>
    /// The store root is NOT set here. It is resolved from the consuming project's folder by a
    /// <c>[SetUpFixture]</c> that each test assembly must carry, because NUnit discovers those only in
    /// the assembly under test. A shared one would point every test assembly at whichever folder this
    /// library happened to be built from, and two assemblies would then fight over one store.
    /// </para>
    /// </summary>
    public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IMonitorTestHelper helper,
                                                                                  Action<MutableConfigurationSection> configuration,
                                                                                  Action<ServiceCollection>? configureServices = null,
                                                                                  CancellationToken token = default )
    {
        var c = ApplicationIdentityServiceConfiguration.Create( helper.Monitor, configuration );
        Throw.DebugAssert( c != null );
        return CreateApplicationServiceAsync( helper, c, configureServices, token );
    }

    /// <summary>
    /// Creates a started service from its configuration. Dispose it to stop its micro agent.
    /// <para>
    /// Only <c>tcp:</c> is registered here. Any another transport — a real one
    /// like <c>mtls:</c>, or a fault-injecting one — must be added through <c>configureServices</c>, which runs
    /// last so it can also replace what this registers: the system clock, in particular, whose fake is
    /// how most timing tests stay fast.
    /// </para>
    /// <para>
    /// The store root is NOT set here. It is resolved from the consuming project's folder by a
    /// <c>[SetUpFixture]</c> that each test assembly must carry, because NUnit discovers those only in
    /// the assembly under test. A shared one would point every test assembly at whichever folder this
    /// library happened to be built from, and two assemblies would then fight over one store.
    /// </para>
    /// </summary>
    public static async Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IMonitorTestHelper helper,
                                                                                        ApplicationIdentityServiceConfiguration c,
                                                                                        Action<ServiceCollection>? configureServices = null,
                                                                                        CancellationToken token = default )
    {
        var serviceBuilder = new ServiceCollection();
        serviceBuilder.AddSingleton( c );
        serviceBuilder.AddSingleton<ApplicationIdentityService>();
        serviceBuilder.AddSingleton<MessageProtocolDirectoryService>();

        // Adds the TransportFeatureDriver before the KeyManagementFeatureDriver to test
        // the existence of the dependency from TransportFeatureDriver to KeyManagementFeatureDriver.
        // (Without the - unused - constructor parameter, registering services in this order fails.)
        serviceBuilder.AddSingleton<TransportFeatureDriver>();
        serviceBuilder.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<TransportFeatureDriver>() );

        serviceBuilder.AddSingleton<IDataProtectionProvider>( sp => FakeProtector.Fake );
        // Resolved lazily: a test that registers its own IDataProtectionProvider (the last registration
        // wins) protects the identity keys with it too.
        serviceBuilder.AddSingleton<DefaultCoreKeyStore>();
        serviceBuilder.AddSingleton<ICoreKeyStore>( sp => sp.GetRequiredService<DefaultCoreKeyStore>() );
        serviceBuilder.AddSingleton<KeyManagementFeatureDriver>();
        serviceBuilder.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<KeyManagementFeatureDriver>() );

        serviceBuilder.AddSingleton<TcpSocketTransportTypeService>();
        serviceBuilder.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<TcpSocketTransportTypeService>() );

        configureServices?.Invoke( serviceBuilder );
        var services = serviceBuilder.BuildServiceProvider();

        var s = services.GetRequiredService<ApplicationIdentityService>();
        // This is done by host. We wait for the FeatureBuildersInitialization task.
        _ = ((IHostedService)s).StartAsync( token );

        await s.InitializationTask.WaitAsync( token ).ConfigureAwait( false );
        return s;
    }

}
