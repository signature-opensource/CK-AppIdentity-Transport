using CK.AppIdentity;
using CK.Core;
using CK.Setup;
using CK.Testing.AppIdentity.TransportLayer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.Testing;

/// <summary>
/// Test helpers for an application that is its own Authentication Center (CK.AppIdentity.AuthCenter.Local) and
/// its HTTP front (CK.Cris.AspNet.Authentication on the endpoint of its "HttpEndpoint" feature): a single process, a
/// single party.
/// </summary>
public static class AuthCenterApplicationTestingExtensions
{
    /// <summary>
    /// Gets the assemblies that make an application its own Authentication Center with an HTTP front (on the endpoint
    /// of its "HttpEndpoint" feature). The login schemes (CK.Cris.Authentication.Basic...), their providers
    /// (CK.DB.User.UserPassword...) and the client packages are added by the test.
    /// </summary>
    public static readonly string[] AuthCenterApplicationAssemblies = ["CK.AppIdentity.AuthCenter.Local",
                                                                       "CK.Cris.AspNet.Authentication",
                                                                       AspNetServerTestHelperExtensions.HttpEndpointAssembly];

    /// <summary>
    /// Adds the <see cref="AuthCenterApplicationAssemblies"/> to this BinPath.
    /// <para>
    /// The HTTP front reads only the commands of the "TypeScript" type set: the BinPath also needs a TypeScript
    /// configuration aspect (a C# only test can use <c>TestHelper.GetTypeScriptGeneratedOnlyTargetProjectPath()</c>).
    /// </para>
    /// </summary>
    /// <param name="binPath">This BinPath configuration.</param>
    /// <returns>This BinPath configuration.</returns>
    public static BinPathConfiguration AddAuthCenterApplication( this BinPathConfiguration binPath )
    {
        binPath.Assemblies.AddRange( AuthCenterApplicationAssemblies );
        return binPath;
    }

    /// <summary>
    /// The default identity of the application: "Test/$AuthCenter" that allows the "AuthCenter" feature in its "Local":
    /// it is its own Authentication Center (with the default settings).
    /// </summary>
    /// <param name="c">The CK-AppIdentity configuration section.</param>
    public static void DefaultIdentity( MutableConfigurationSection c )
    {
        c["FullName"] = "Test/$AuthCenter";
        c["Local:AllowFeatures"] = "AuthCenter";
    }

    /// <summary>
    /// Creates and starts the application, a party (see <see cref="AspNetServerTestHelperExtensions.CreateRunningAspNetServerAsync(IStObjMap, Action{MutableConfigurationSection}?, Action{HostApplicationBuilder}?, Action{WebApplicationBuilder}?)"/>):
    /// its identity (<see cref="DefaultIdentity"/> by default), a fake data protection (the identity keys are not really
    /// protected at rest). The Cris authentication and Cris middlewares are the contributions of their packages to its
    /// endpoint. The returned server's identity service is initialized.
    /// </summary>
    /// <param name="map">The StObjMap of a BinPath with <see cref="AddAuthCenterApplication"/>.</param>
    /// <param name="identity">Configures the identity of the application. Defaults to <see cref="DefaultIdentity"/>.</param>
    /// <param name="configureHost">Optional configuration of the host, before the map is registered.</param>
    /// <param name="configureEndpoint">Optional configuration of the web application of the endpoint.</param>
    /// <returns>The running server.</returns>
    public static async Task<RunningAspNetServer> CreateRunningAuthCenterApplicationAsync( this IStObjMap map,
                                                                                           Action<MutableConfigurationSection>? identity = null,
                                                                                           Action<HostApplicationBuilder>? configureHost = null,
                                                                                           Action<WebApplicationBuilder>? configureEndpoint = null )
    {
        var server = await map.CreateRunningAspNetServerAsync( identity ?? DefaultIdentity,
                                                               b =>
                                                               {
                                                                   b.Services.AddSingleton<IDataProtectionProvider>( FakeProtector.Fake );
                                                                   configureHost?.Invoke( b );
                                                               },
                                                               configureEndpoint );
        await server.Services.GetRequiredService<ApplicationIdentityService>().InitializationTask;
        return server;
    }
}
