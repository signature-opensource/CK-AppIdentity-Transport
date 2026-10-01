using CK.AppIdentity;
using CK.Core;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.Testing;

public static class AppIdentityCrisTestingExtensions
{
    /// <summary>
    /// Creates a running "Test/$Sender" application that initiate connections to a "Test/$Listener" remote.
    /// </summary>
    /// <param name="configuration">
    /// Optional configurator for the <see cref="MutableConfigurationSection"/>.
    /// Used by <see cref="ApplicationIdentityServiceConfiguration.Create(IActivityMonitor, Action{MutableConfigurationSection})"/>.
    /// This is called after the $Sender configuration: anything can be changed.
    /// </param>
    /// <param name="configureServices">
    /// Optional services configuration. Calls after the default services initialization: services can be overridden as needed.
    /// </param>
    /// <param name="types">
    /// Types to register. Fills the <see cref="Setup.BinPathConfiguration.Types"/>.
    /// </param>
    /// <returns>A running application.</returns>
    public static Task<RunningApplication> CreateCrisSenderApplicationAsync( this IMonitorTestHelper @this,
                                                                             Action<MutableConfigurationSection>? configuration,
                                                                             Action<IServiceCollection>? configureServices,
                                                                             params Type[] types )
    {
        return RunningApplication.CreateAsync( @this.Monitor, true, configuration, configureServices, types );
    }

    /// <summary>
    /// Creates a running "Test/$Listener" server application that declares a "Test/$Sender" remote.
    /// </summary>
    /// <param name="configuration">
    /// Optional configurator for the <see cref="MutableConfigurationSection"/>.
    /// Used by <see cref="ApplicationIdentityServiceConfiguration.Create(IActivityMonitor, Action{MutableConfigurationSection})"/>.
    /// This is called after the $Listener configuration: anything can be changed.
    /// </param>
    /// <param name="configureServices">
    /// Optional services configuration. Calls after the default services initialization: services can be overridden as needed.
    /// </param>
    /// <param name="types">
    /// Types to register. Fills the <see cref="Setup.BinPathConfiguration.Types"/>.
    /// </param>
    /// <returns>A running application.</returns>
    public static Task<RunningApplication> CreateCrisListenerApplicationAsync( this IMonitorTestHelper @this,
                                                                               Action<MutableConfigurationSection>? configuration,
                                                                               Action<IServiceCollection>? configureServices,
                                                                               params Type[] types )
    {
        return RunningApplication.CreateAsync( @this.Monitor, false, configuration, configureServices, types );
    }


}
