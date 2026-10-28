using CK.AppIdentity;
using CK.Core;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.AppIdentity.Tests;

public class PartyActorFeatureDriverTests
{
    static PartyActorTable Table => SharedEngine.Map.StObjs.Obtain<PartyActorTable>().ShouldNotBeNull();

    static async Task<ApplicationIdentityService> StartAsync( Action<MutableConfigurationSection> configuration )
    {
        var c = ApplicationIdentityServiceConfiguration.Create( TestHelper.Monitor, configuration ).ShouldNotBeNull();
        var services = new ServiceCollection();
        services.AddSingleton( c );
        services.AddSingleton<ApplicationIdentityService>();
        services.AddSingleton( Table );
        services.AddSingleton<PartyActorFeatureDriver>();
        services.AddSingleton<IApplicationIdentityFeatureDriver>( sp => sp.GetRequiredService<PartyActorFeatureDriver>() );
        var s = services.BuildServiceProvider().GetRequiredService<ApplicationIdentityService>();
        _ = ((IHostedService)s).StartAsync( default );
        try
        {
            await s.InitializationTask;
        }
        catch
        {
            await s.DisposeAsync();
            throw;
        }
        return s;
    }

    // Party names are short: 8 random characters are enough to isolate a test run.
    static string NewDomainName() => $"PA{Guid.NewGuid().ToString( "N" )[..8]}";

    static async Task<int> IdOfAsync( IParty party )
    {
        using var context = new SqlStandardCallContext( TestHelper.Monitor );
        return await Table.EnsureAsync( context, 1, party.FullName );
    }

    [Test]
    public async Task all_the_parties_get_their_PartyActorId_Async()
    {
        var domain = NewDomainName();
        await using var s = await StartAsync( c =>
        {
            c["FullName"] = $"{domain}/$App";
            c["Parties:0:PartyName"] = "Remote1";
            c["Parties:1:PartyName"] = "NoId";
            c["Parties:1:DisallowFeatures"] = "PartyActor";
            // A tenant domain: its party name is its domain name.
            c["Parties:2:FullName"] = $"{domain}T/${domain}T";
            c["Parties:2:Parties:0:PartyName"] = "TenantRemote";
        } );
        var tenant = s.TenantDomains.Single();
        var all = new IParty[] { s, s.Remotes.Single( r => r.PartyName == "$Remote1" ), tenant, tenant.Remotes.Single() };
        foreach( var p in all )
        {
            p.PartyActorId.ShouldBeGreaterThan( 0, p.FullName );
            p.PartyActorId.ShouldBe( await IdOfAsync( p ), p.FullName );
        }
        all.Select( p => p.PartyActorId ).Distinct().Count().ShouldBe( all.Length );
        s.Remotes.Single( r => r.PartyName == "$NoId" ).PartyActorId.ShouldBe( 0, "The feature is disallowed for it." );
    }

    [Test]
    public async Task a_dynamic_remote_gets_its_PartyActorId_Async()
    {
        var domain = NewDomainName();
        await using var s = await StartAsync( c => c["FullName"] = $"{domain}/$App" );
        var remotes = await s.AddMultipleRemotesAsync( TestHelper.Monitor, c => c["PartyName"] = "Dynamic" );
        var dynamic = remotes.ShouldNotBeNull().Single();
        dynamic.PartyActorId.ShouldBeGreaterThan( 0 );
        dynamic.PartyActorId.ShouldBe( await IdOfAsync( dynamic ) );
    }

    [Test]
    public async Task a_restarted_application_gets_the_same_ids_Async()
    {
        var domain = NewDomainName();
        Action<MutableConfigurationSection> config = c =>
        {
            c["FullName"] = $"{domain}/$App";
            c["Parties:0:PartyName"] = "Remote";
        };
        int appId, remoteId;
        await using( var s = await StartAsync( config ) )
        {
            appId = s.PartyActorId;
            remoteId = s.Remotes.Single().PartyActorId;
        }
        await using( var s = await StartAsync( config ) )
        {
            s.PartyActorId.ShouldBe( appId );
            s.Remotes.Single().PartyActorId.ShouldBe( remoteId );
        }
    }
}
