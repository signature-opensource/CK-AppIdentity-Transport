using CK.AppIdentity.TransportLayer.Testing;
using CK.Core;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// The shared builder plus this assembly's own fault-injecting transport.
/// <para>
/// <see cref="BugTransportTypeService"/> stays here rather than in the Testing project: it exists to
/// make connect, read, write and dispose fail on demand, which is this assembly's subject and nobody
/// else's.
/// </para>
/// </summary>
static class TestHelperExtension
{
    /// <summary>
    /// Creates a <see cref="ApplicationIdentityService"/> from a configuration builder.
    /// It must be disposed once done with it to stop its micro agent.
    /// </summary>
    public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                  Action<MutableConfigurationSection> configuration,
                                                                                  Action<ServiceCollection>? configureServices = null,
                                                                                  CancellationToken token = default )
        => AppIdentityTestHelper.CreateServiceAsync( configuration, WithBugTransport( configureServices ), token );

    /// <summary>
    /// Creates a <see cref="ApplicationIdentityService"/> from its configuration.
    /// It must be disposed once done with it to stop its micro agent.
    /// </summary>
    public static Task<ApplicationIdentityService> CreateApplicationServiceAsync( this IBasicTestHelper @this,
                                                                                  ApplicationIdentityServiceConfiguration c,
                                                                                  Action<ServiceCollection>? configureServices = null,
                                                                                  CancellationToken token = default )
        => AppIdentityTestHelper.CreateServiceAsync( c, WithBugTransport( configureServices ), token );

    // Registered before the caller's own configuration, so a test can still replace anything here.
    static Action<ServiceCollection> WithBugTransport( Action<ServiceCollection>? configureServices )
        => services =>
        {
            services.AddSingleton<BugTransportTypeService>();
            services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<BugTransportTypeService>() );
            configureServices?.Invoke( services );
        };
}
