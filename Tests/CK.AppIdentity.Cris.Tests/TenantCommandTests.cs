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
/// The hub of the System's administration (<see cref="IPartyRelay"/>, its directory <see cref="IGetAcceptingRemotesQCommand"/>)
/// and the tenant commands (CK.AppIdentity.Tenants): three parties, "Test/$Sender" &gt; "Test/$Listener" &lt; "Test/$C".
/// The listener stands for the Authentication Center: it is the hub of the sender.
/// </summary>
[TestFixture]
public class TenantCommandTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    public interface IEchoPartyCommand : ICommand<string>, ICommandTargetParty
    {
    }

    public sealed class EchoHandler : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IEchoPartyCommand c, CurrentLocalParty party ) => party.LocalParty.FullName;
    }

    // The hub of a local party is its only remote (the listener): CK.AppIdentity.AuthCenter's relay gives its remote AuthCenter.
    public sealed class SingleRemoteHub : IPartyRelay
    {
        public IRemoteParty? GetHub( ILocalParty local ) => local.Remotes.Count == 1 ? local.Remotes.Single() : null;
    }

    static readonly Type[] _common = [typeof( IPartyRoutedCommand ),
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( RoutedCommandTests.RecordingReceptionHandler ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( IEchoPartyCommand ),
                                      typeof( IGetAcceptingRemotesQCommand ),
                                      typeof( AcceptingRemotesHandler ),
                                      typeof( ReceptionTests.ITestEnvelope ),
                                      typeof( IPartySealedResult )];

    static async Task<IExecutedCommand> ExecuteAsync( RunningApplication app, IAbstractCommand command )
    {
        using var scope = app.CreateScopeServices();
        var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
        return await app.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, command, hub ).ExecutedCommand.WaitAsync( _timeout );
    }

    static async Task<bool> WaitForAcceptedAsync( RunningApplication app, string remote )
    {
        var channel = app.ApplicationIdentityService.Remotes.Single( r => r.FullName == remote ).GetRequiredFeature<CrisChannelFeature>();
        return await channel.WaitForAcceptedCommandsAsync( _timeout );
    }

    [Test]
    public async Task a_party_command_for_a_party_that_is_not_a_remote_goes_through_the_hub_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( SingleRemoteHub )],
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
                                                                  [.. _common, typeof( EchoHandler )] );
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;
        (await WaitForAcceptedAsync( a, bName )).ShouldBeTrue();
        (await WaitForAcceptedAsync( b, cName )).ShouldBeTrue();

        // C is not a remote of the sender: the command goes through its hub (the listener), that has C as a remote.
        (await ExecuteAsync( a, a.PocoDirectory.Create<IEchoPartyCommand>( e => e.TargetPartyFullName = cName ) )).Result.ShouldBe( cName );
        // A party that the hub doesn't know: the hub refuses it.
        (await ExecuteAsync( a, a.PocoDirectory.Create<IEchoPartyCommand>( e => e.TargetPartyFullName = "Test/$Nobody/#Dev" ) ))
            .Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().Text.ShouldContain( "is not a remote of" );
        // The hub is the directory: it lists its remotes that accept a command.
        var accepting = await ExecuteAsync( a, a.PocoDirectory.Create<IGetAcceptingRemotesQCommand>( q =>
        {
            q.TargetPartyFullName = bName;
            q.CommandName = a.PocoDirectory.Create<IEchoPartyCommand>().CrisPocoModel.PocoName;
        } ) );
        accepting.Result.ShouldBeAssignableTo<System.Collections.Generic.IList<string>>()!.ShouldContain( cName );
    }

    static readonly Type[] _tenants = [typeof( AuthenticationInfo ),
                                       typeof( TenantHandlers ),
                                       typeof( IGetTenantHostsQCommand ),
                                       typeof( IGetTenantInstancesQCommand ),
                                       typeof( ITenantTemplateInfo ),
                                       typeof( ITenantInstanceInfo ),
                                       typeof( ICreateTenantInstanceCommand ),
                                       typeof( ISetTenantIndexCommand ),
                                       typeof( IRemoveTenantInstanceCommand )];

    [Test]
    public async Task the_tenant_holders_are_found_through_the_hub_and_their_tenants_are_managed_Async()
    {
        var store = ApplicationIdentityServiceConfiguration.DefaultStoreRootPath.Combine( "#Dev/Test/CrisTenants" );
        if( System.IO.Directory.Exists( store ) ) System.IO.Directory.Delete( store, recursive: true );
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, .. _tenants, typeof( SingleRemoteHub )],
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
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;
        (await WaitForAcceptedAsync( a, bName )).ShouldBeTrue();
        (await WaitForAcceptedAsync( b, cName )).ShouldBeTrue();

        // The application of the page finds C through its hub: C accepts the tenant commands, the hub doesn't, and the
        // page's application has no template.
        var aHandlers = a.Services.GetRequiredService<TenantHandlers>();
        await using( var aScope = a.CreateAsyncScopeServices() )
        {
            (await aHandlers.HandleAsync( TestHelper.Monitor,
                                          a.PocoDirectory.Create<IGetTenantHostsQCommand>(),
                                          new CurrentLocalParty( a.ApplicationIdentityService ),
                                          a.PocoDirectory,
                                          aScope.ServiceProvider )).ShouldBe( [cName] );
        }

        // On the holder: create, list, move, remove (the Critical level is the one of the dispatched commands: here the
        // handlers are called directly).
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
