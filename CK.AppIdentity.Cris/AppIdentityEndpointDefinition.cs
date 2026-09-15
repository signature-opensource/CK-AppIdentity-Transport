using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Diagnostics.CodeAnalysis;

namespace CK.AppIdentity.Cris;


[DIContainerDefinition( DIContainerKind.Endpoint )]
public abstract class AppIdentityEndpointDefinition : DIContainerDefinition<AppIdentityEndpointDefinition.Data>
{
    public sealed class Data : IScopedData
    {
        [AllowNull]
        internal CrisJob _job;
        internal readonly string? _authenticationToken;

        public Data( string? authenticationToken )
        {
            _authenticationToken = authenticationToken;
        }
    }

    public override void ConfigureContainerServices( IServiceCollection services,
                                                     Func<IServiceProvider, Data> scopeData,
                                                     IServiceProviderIsService globalServiceExists )
    {
        services.AddScoped( sp => scopeData( sp )._job.RunnerMonitor! );
        services.AddScoped( sp => scopeData( sp )._job.RunnerMonitor!.ParallelLogger );
        services.AddScoped( sp => scopeData( sp )._job.ExecutionContext! );
        services.AddScoped<ICrisEventContext>( sp => scopeData( sp )._job.ExecutionContext! );
    }

}
