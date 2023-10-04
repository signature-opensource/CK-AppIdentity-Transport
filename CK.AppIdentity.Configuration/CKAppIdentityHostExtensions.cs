using CK.AppIdentity;
using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Microsoft.Extensions.Hosting
{

    /// <summary>
    /// Adds extension methods on <see cref="IHostBuilder"/>.
    /// </summary>
    public static class CKAppIdentityHostExtensions
    {
        /// <summary>
        /// Initializes this application identity from "CK-AppIdentity" configuration section.
        /// This injects a configured instance of <see cref="ApplicationIdentityServiceConfiguration"/> as
        /// a singleton service in the DI container and initializes <see cref="CoreApplicationIdentity"/>
        /// </summary>
        /// <param name="builder">This host builder</param>
        /// <param name="contextDescriptor">Defaults to <see cref="Environment.CommandLine"/>.</param>
        /// <returns>The builder.</returns>
        public static IHostBuilder UseCKAppIdentity( this IHostBuilder builder, string? contextDescriptor = null )
        {
            var monitor = builder.GetBuilderMonitor();
            builder.ConfigureServices( (ctx,services) =>
            {
                var appIdentity = ApplicationIdentityServiceConfiguration.Create( monitor, ctx.HostingEnvironment, ctx.Configuration.GetSection( "CK-AppIdentity" ) );
                if( appIdentity != null )
                {

                    if( CoreApplicationIdentity.TryConfigure( identity =>
                    {
                        identity.DomainName = appIdentity.DomainName;
                        identity.PartyName = appIdentity.PartyName;
                        identity.EnvironmentName = appIdentity.EnvironmentName;
                        identity.ContextDescriptor = contextDescriptor ?? Environment.CommandLine;
                    } ) )
                    {
                        CoreApplicationIdentity.Initialize();
                    }
                    else
                    {
                        monitor.Warn( "Unable to configure CoreApplicationIdentity since it is already initialized." );
                    }
                    services.AddSingleton( appIdentity );
                }
            } );
            return builder;
        }
    }
}
