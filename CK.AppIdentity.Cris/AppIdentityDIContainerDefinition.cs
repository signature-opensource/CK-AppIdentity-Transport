using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.Cris;


[DIContainerDefinition( DIContainerKind.Endpoint )]
public abstract class AppIdentityDIContainerDefinition : DIContainerDefinition<AppIdentityDIContainerDefinition.Data>
{
    /// <summary>
    /// In this context, we ALWAYS have a IRemoteParty to inject as a scoped service.
    /// </summary>
    public sealed class Data : IScopedData
    {
        [AllowNull]
        internal CrisJob _job;
        [AllowNull]
        internal CrisChannelFeature.Protocol _handler;
        internal readonly IRemoteParty _remoteParty;

        public Data( IRemoteParty remoteParty )
        {
            _remoteParty = remoteParty;
        }
    }

    public override void ConfigureContainerServices( IServiceCollection services,
                                                     Func<IServiceProvider, Data> scopeData,
                                                     IServiceProviderIsService globalServiceExists )
    {
        services.AddScoped( sp => scopeData( sp )._job.RunnerMonitor! );
        services.AddScoped( sp => scopeData( sp )._job.RunnerMonitor!.ParallelLogger );
        // ICrisCommandContext and ICrisEventContext.
        services.AddScoped( sp => scopeData( sp )._job.ExecutionContext! );
        services.AddScoped<ICrisEventContext>( sp => scopeData( sp )._job.ExecutionContext! );
        // Adds the IRemoteParty as a resolvable scoped service.
        services.AddScoped( sp => scopeData( sp )._remoteParty );
        // The CurrentLocalParty ambient service is not the default one but the owner of the remote here.
        services.AddScoped( sp => new CurrentLocalParty( scopeData( sp )._remoteParty.Owner ) );
    }

}
