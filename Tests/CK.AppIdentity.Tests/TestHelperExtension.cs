using CK.Core;
using CK.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting.Internal;
using System;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Tests
{
    static class TestHelperExtension
    {

        public static AppIdentityConfiguration CreateAppIdentityConfiguration( this IBasicTestHelper helper,
                                                                               Action<IConfigurationSection>? appIdentitySection = null,
                                                                               string hostApplicationName = "MyApp",
                                                                               string hostEnvironmentName = "MyEnvironment" )
        {
            using var config = new ConfigurationManager();
            config.Add<DynamicConfigurationSource>( Util.ActionVoid );
            var section = config.GetSection( "CK-AppIdentity" );
            appIdentitySection?.Invoke( section );
            var hostEnv = new HostingEnvironment()
            {
                ApplicationName = hostApplicationName,
                EnvironmentName = hostEnvironmentName,
            };
            return AppIdentityConfiguration.Create( TestHelper.Monitor, hostEnv, section )!;
        }
    }
}
