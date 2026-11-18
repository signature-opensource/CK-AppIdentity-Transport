using CK.AppIdentity.Tenants;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Tenants;
using CK.Testing.Engine.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The party commands beyond one hop (<see cref="IPartyCommandRouteProvider"/>) and the tenant commands
/// (CK.AppIdentity.Tenants): three parties in a chain, "Test/$Sender" &gt; "Test/$Listener" &lt; "Test/$C".
/// </summary>
[TestFixture]
public class TenantCommandTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    public interface IRoutedEchoCommand : ICommand<string>, ICommandTargetParty
    {
    }

    public interface IUnroutedEchoCommand : ICommand<string>, ICommandTargetParty
    {
    }

    public sealed class EchoHandlers : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IRoutedEchoCommand c, CurrentLocalParty party ) => party.LocalParty.FullName;

        [CommandHandler]
        public string Handle( IUnroutedEchoCommand c, CurrentLocalParty party ) => party.LocalParty.FullName;
    }

    // The package of IRoutedEchoCommand names its route.
    public sealed class EchoRouteProvider : IPartyCommandRouteProvider
    {
        public string? GetRouteName( IAbstractCommand command ) => command is IRoutedEchoCommand ? "Routed" : null;
    }

    static readonly Type[] _common = [typeof( IPartyRoutedCommand ),
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( RoutedCommandTests.RecordingReceptionHandler ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( IRoutedEchoCommand ),
                                      typeof( IUnroutedEchoCommand ),
                                      typeof( ReceptionTests.ITestEnvelope ),
                                      typeof( IPartySealedResult )];

    static async Task<IExecutedCommand> ExecuteAsync( RunningApplication app, IAbstractCommand command )
    {
        using var scope = app.CreateScopeServices();
        var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
        return await app.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, command, hub ).ExecutedCommand.WaitAsync( _timeout );
    }

    static async Task<bool> WaitForRouteAsync( ILocalParty local, string name )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( local.Description.Routes.ContainsKey( name ) ) return true;
            await Task.Delay( 100 );
        }
        return false;
    }

    [Test]
    public async Task a_party_command_beyond_one_hop_travels_along_the_route_its_package_names_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( EchoRouteProvider )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:KeyManagement:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: _common );
        var (a, b) = pair;
        await using var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$C",
                                                                  null,
                                                                  [.. _common, typeof( EchoHandlers ), typeof( RoutedCommandTests.RouteHostFeatureDriver )] );
        string cName = c.ApplicationIdentityService.FullName;
        (await WaitForRouteAsync( a.ApplicationIdentityService, "Routed" )).ShouldBeTrue();

        // C is not a remote of the sender: the command travels along "Routed" (through the listener).
        (await ExecuteAsync( a, a.PocoDirectory.Create<IRoutedEchoCommand>( e => e.TargetPartyFullName = cName ) )).Result.ShouldBe( cName );
        // No package names the route of this one: no route, as before.
        (await ExecuteAsync( a, a.PocoDirectory.Create<IUnroutedEchoCommand>( e => e.TargetPartyFullName = cName ) ))
            .Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().ResName.ShouldBe( "Cris.NoRoute" );
    }

    static readonly Type[] _tenants = [typeof( AuthenticationInfo ),
                                       typeof( TenantsFeatureDriver ),
                                       typeof( TenantHandlers ),
                                       typeof( TenantCommandRouteProvider ),
                                       typeof( IGetTenantHostsQCommand ),
                                       typeof( IGetTenantInstancesQCommand ),
                                       typeof( ITenantTemplateInfo ),
                                       typeof( ITenantInstanceInfo ),
                                       typeof( ICreateTenantInstanceCommand ),
                                       typeof( ISetTenantIndexCommand ),
                                       typeof( IRemoveTenantInstanceCommand )];

    [Test]
    public async Task the_tenant_commands_reach_the_holder_of_the_templates_and_manage_its_tenants_Async()
    {
        var store = ApplicationIdentityServiceConfiguration.DefaultStoreRootPath.Combine( "#Dev/Test/CrisTenants" );
        if( System.IO.Directory.Exists( store ) ) System.IO.Directory.Delete( store, recursive: true );
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, .. _tenants],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:KeyManagement:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: _common );
        var (a, b) = pair;
        await using var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c =>
                                                                  {
                                                                      c["FullName"] = "Test/$C";
                                                                      c["Parties:1:DomainName"] = "Test/CrisTenants/{Name}";
                                                                      c["Parties:1:PartyName"] = "${Name}";
                                                                      c["Parties:1:InstanceCount"] = "0";
                                                                      c["Parties:1:MaxInstanceCount"] = "2";
                                                                  },
                                                                  null,
                                                                  [.. _common, .. _tenants] );
        string cName = c.ApplicationIdentityService.FullName;

        // The holder hosts "Tenants": the host of the page finds it (its route travels through the listener).
        (await WaitForRouteAsync( a.ApplicationIdentityService, TenantsFeatureDriver.RouteName )).ShouldBeTrue();
        var aHandlers = a.Services.GetRequiredService<TenantHandlers>();
        aHandlers.Handle( a.PocoDirectory.Create<IGetTenantHostsQCommand>(), new CurrentLocalParty( a.ApplicationIdentityService ) )
                 .ShouldBe( [cName] );
        // A tenant command to the holder travels along "Tenants".
        a.Services.GetServices<IPartyCommandRouteProvider>().Select( p => p.GetRouteName( a.PocoDirectory.Create<ICreateTenantInstanceCommand>() ) )
                  .ShouldContain( TenantsFeatureDriver.RouteName );

        // On the holder: create, list, move, remove.
        var handlers = c.Services.GetRequiredService<TenantHandlers>();
        var cLocal = new CurrentLocalParty( c.ApplicationIdentityService );
        await using var scope = c.CreateAsyncScopeServices();
        UserMessageCollector Messages() => new UserMessageCollector( scope.ServiceProvider.GetRequiredService<CurrentCultureInfo>() );

        var created = await handlers.HandleAsync( TestHelper.Monitor,
                                                  c.PocoDirectory.Create<ICreateTenantInstanceCommand>( x => { x.TemplateName = "Test/CrisTenants"; x.Name = "Acme"; } ),
                                                  cLocal,
                                                  Messages() );
        created.ShouldBe( "Test/CrisTenants/Acme/$Acme/#Dev" );
        var unknown = Messages();
        (await handlers.HandleAsync( TestHelper.Monitor,
                                     c.PocoDirectory.Create<ICreateTenantInstanceCommand>( x => { x.TemplateName = "Test/Nowhere"; x.Name = "Acme"; } ),
                                     cLocal,
                                     unknown )).ShouldBeNull();
        unknown.UserMessages.ShouldContain( m => m.ResName == "AppIdentity.Tenants.UnknownTemplate" );

        var template = handlers.Handle( c.PocoDirectory.Create<IGetTenantInstancesQCommand>(), cLocal, c.PocoDirectory ).ShouldHaveSingleItem();
        template.TemplateName.ShouldBe( "Test/CrisTenants" );
        template.MaxInstanceCount.ShouldBe( 2 );
        var acme = template.Instances.ShouldHaveSingleItem();
        (acme.Name, acme.Index, acme.IsConfigured, acme.UnloadedReason).ShouldBe( ("Acme", 1, false, null) );

        (await handlers.HandleAsync( TestHelper.Monitor,
                                     c.PocoDirectory.Create<ISetTenantIndexCommand>( x => { x.TenantFullName = created!; x.Index = 2; } ),
                                     cLocal,
                                     Messages() )).ShouldBeTrue();
        handlers.Handle( c.PocoDirectory.Create<IGetTenantInstancesQCommand>(), cLocal, c.PocoDirectory ).Single().Instances.Single().Index.ShouldBe( 2 );

        (await handlers.HandleAsync( TestHelper.Monitor,
                                     c.PocoDirectory.Create<IRemoveTenantInstanceCommand>( x => x.TenantFullName = created! ),
                                     cLocal,
                                     Messages() )).ShouldBeTrue();
        handlers.Handle( c.PocoDirectory.Create<IGetTenantInstancesQCommand>(), cLocal, c.PocoDirectory ).Single().Instances.ShouldBeEmpty();
    }
}
