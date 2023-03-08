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
        /// This injects a configured instance of <see cref="AppIdentityConfiguration"/> as a singleton service in the
        /// DI container and initializes <see cref="CoreApplicationIdentity"/>
        /// </summary>
        /// <param name="builder">This host builder</param>
        /// <param name="contextDescriptor">Defaults to <see cref="Environment.CommandLine"/>.</param>
        /// <returns>The builder.</returns>
        public static IHostBuilder UseCKAppIdentity( this IHostBuilder builder, string? contextDescriptor = null )
        {
            // UseCKMonitoring can be called more than once.
            builder.UseCKMonitoring();
            var monitor = builder.GetBuilderMonitor();
            builder.ConfigureServices( (ctx,services) =>
            {
                var appIdentity = AppIdentityConfiguration.Create( monitor, ctx.HostingEnvironment, ctx.Configuration.GetSection( "CK-AppIdentity" ) );
                if( appIdentity != null )
                {

                    if( !CoreApplicationIdentity.TryConfigure( identity =>
                    {
                        identity.PartyName = appIdentity.Local.Name;
                        identity.EnvironmentName = appIdentity.EnvironmentName;
                        identity.DomainName = appIdentity.DomainName;
                        identity.ContextDescriptor = contextDescriptor ?? Environment.CommandLine;
                    } ) )
                    {
                        monitor.Warn( "Unable to configure CoreApplicationIdentity since it is already initialized." );
                    }
                    else
                    {
                        CoreApplicationIdentity.Initialize();
                    }
                    services.AddSingleton( appIdentity );
                }
            } );
            return builder;
        }
    }
}
