using CK.Core;
using CK.Cris;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The location-transparent dispatch over the Cris channels (<see cref="ChannelCrisRemoteDispatcher"/>): a command without
/// local handler executes on the remote that accepts it, a party command executes where its target is.
/// </summary>
public class DispatchTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    public interface IPingCommand : ICommand<string>
    {
        string Text { get; set; }
    }

    [Internal]
    public interface IInternalPingCommand : ICommand<string>
    {
    }

    [Private]
    public interface IPrivatePingCommand : ICommand<string>
    {
    }

    // Handled nowhere.
    public interface INobodyCommand : ICommand<string>
    {
    }

    // Handled by both applications: answers the full name of its current local party.
    public interface IPartyEchoCommand : ICommand<string>, ICommandTargetParty
    {
    }

    // A caller-only final event: it travels with the response.
    public interface IPongEvent : IEvent
    {
        string Text { get; set; }
    }

    // A caller-only immediate event.
    [ImmediateEvent]
    public interface IPongImmediateEvent : IEvent
    {
    }

    // The listener's handlers.
    public sealed class ListenerSide : ISingletonAutoService
    {
        [CommandHandler]
        public async Task<string> HandleAsync( IPingCommand c, ICrisCommandContext context )
        {
            await context.EmitEventAsync<IPongImmediateEvent>( _ => { } );
            await context.EmitEventAsync<IPongEvent>( e => e.Text = c.Text );
            return $"pong:{c.Text}";
        }

        [CommandHandler]
        public string Handle( IInternalPingCommand c ) => "internal";

        [CommandHandler]
        public string Handle( IPrivatePingCommand c ) => "private";
    }

    public sealed class BothSides : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IPartyEchoCommand c, CurrentLocalParty party ) => party.LocalParty.FullName;
    }

    static readonly Type[] _common = [typeof( IPingCommand ),
                                      typeof( IInternalPingCommand ),
                                      typeof( IPrivatePingCommand ),
                                      typeof( INobodyCommand ),
                                      typeof( IPartyEchoCommand ),
                                      typeof( IPongEvent ),
                                      typeof( IPongImmediateEvent ),
                                      typeof( BothSides ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( CommandTargetPartyValidator )];

    static Task<RunningApplication> StartSenderAsync( Action<MutableConfigurationSection>? configuration = null )
        => RunningApplication.CreateAsync( TestHelper.Monitor, true, configuration, null, _common );

    static Task<RunningApplication> StartListenerAsync( Action<MutableConfigurationSection>? configuration = null )
        => RunningApplication.CreateAsync( TestHelper.Monitor, false, configuration, null, [.. _common, typeof( ListenerSide )] );

    // Executes a command on the application (in the background: with an execution context), with the ambient services
    // of the application. (Without a hub, the background restores them through a static of the generated code: the
    // applications of a test process share it, it would be the first application's.)
    static async Task<IExecutedCommand> ExecuteAsync( RunningApplication app, IAbstractCommand command )
        => await Submit( app, command ).ExecutedCommand.WaitAsync( _timeout );

    static IExecutingCommand Submit( RunningApplication app, IAbstractCommand command )
    {
        using var scope = app.CreateScopeServices();
        var hub = scope.ServiceProvider.GetRequiredService<AmbientServiceHub>().CleanClone();
        return app.Services.GetRequiredService<CrisBackgroundExecutorService>().Submit( TestHelper.Monitor, command, hub );
    }

    static string Error( IExecutedCommand executed ) => executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().ResName;

    [Test]
    public async Task a_command_without_local_handler_executes_on_the_remote_that_accepts_it_Async()
    {
        await using var sender = await StartSenderAsync();
        await using var listener = await StartListenerAsync();

        var executing = Submit( sender, sender.PocoDirectory.Create<IPingCommand>( c => c.Text = "hi" ) );
        var executed = await executing.ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBe( "pong:hi" );
        // The caller-only events travel with the response.
        executed.Events.OfType<IPongEvent>().ShouldHaveSingleItem().Text.ShouldBe( "hi" );
        executing.ImmediateEvents.OfType<IPongImmediateEvent>().ShouldHaveSingleItem();

        // [Internal]: accepted from a remote inside the System.
        (await ExecuteAsync( sender, sender.PocoDirectory.Create<IInternalPingCommand>() )).Result.ShouldBe( "internal" );

        // Handled nowhere: no route.
        Error( await ExecuteAsync( sender, sender.PocoDirectory.Create<INobodyCommand>() ) ).ShouldBe( "Cris.NoRoute" );

        // [Private]: never dispatched, and refused when sent explicitly.
        Error( await ExecuteAsync( sender, sender.PocoDirectory.Create<IPrivatePingCommand>() ) ).ShouldBe( "Cris.MissingCommandHandler" );
        var refused = await sender.CrisChannel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IPrivatePingCommand>() ).ExecutedCommand.WaitAsync( _timeout );
        refused.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().Text.ShouldContain( "is not accepted" );
    }

    [Test]
    public async Task a_party_command_executes_where_its_target_is_Async()
    {
        // The sender has a tenant domain (its party name is its domain name).
        await using var sender = await StartSenderAsync( c => c["Parties:1:FullName"] = "Tenant/$Tenant" );
        await using var listener = await StartListenerAsync();
        var senderName = sender.ApplicationIdentityService.FullName.Path;
        var listenerName = listener.ApplicationIdentityService.FullName.Path;
        var tenantName = sender.ApplicationIdentityService.TenantDomains.Single().FullName.Path;

        IPartyEchoCommand Echo( string target ) => sender.PocoDirectory.Create<IPartyEchoCommand>( c => c.TargetPartyFullName = target );

        (await ExecuteAsync( sender, Echo( senderName ) )).Result.ShouldBe( senderName );
        // Sent to the remote although the command is handled here.
        (await ExecuteAsync( sender, Echo( listenerName ) )).Result.ShouldBe( listenerName );
        // Another local party: executed here, with it as the current local party.
        (await ExecuteAsync( sender, Echo( tenantName ) )).Result.ShouldBe( tenantName );
        Error( await ExecuteAsync( sender, Echo( "Nowhere/$Nobody/#Dev" ) ) ).ShouldBe( "Cris.NoRoute" );

        // A party command received for another party is refused.
        var wrong = await sender.CrisChannel.SendCommand( TestHelper.Monitor, Echo( senderName ) ).ExecutedCommand.WaitAsync( _timeout );
        wrong.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().Text.ShouldContain( "doesn't target this party" );
    }

    [Test]
    public async Task an_Internal_command_is_refused_from_a_remote_outside_the_System_Async()
    {
        // The sender is in another domain: outside the System of the listener.
        await using var sender = await StartSenderAsync( c =>
        {
            c["FullName"] = "Other/$Sender";
            c["Parties:0:PartyName"] = null;
            c["Parties:0:FullName"] = "Test/$Listener";
        } );
        await using var listener = await StartListenerAsync( c =>
        {
            c["Parties:0:PartyName"] = null;
            c["Parties:0:FullName"] = "Other/$Sender";
        } );

        // Public: accepted.
        (await ExecuteAsync( sender, sender.PocoDirectory.Create<IPingCommand>( c => c.Text = "x" ) )).Result.ShouldBe( "pong:x" );
        // [Internal]: not advertised (no route) and refused when sent explicitly.
        Error( await ExecuteAsync( sender, sender.PocoDirectory.Create<IInternalPingCommand>() ) ).ShouldBe( "Cris.NoRoute" );
        var refused = await sender.CrisChannel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IInternalPingCommand>() ).ExecutedCommand.WaitAsync( _timeout );
        refused.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.First().Text.ShouldContain( "is not accepted" );
    }

    [Test]
    public async Task a_dispatch_waits_for_the_first_advertisement_of_the_remotes_Async()
    {
        await using var sender = await StartSenderAsync();
        // The listener doesn't exist yet: the dispatch waits for its advertisement (up to the timeout).
        var executing = Submit( sender, sender.PocoDirectory.Create<IPingCommand>( c => c.Text = "early" ) );
        sender.CrisChannel.AcceptedCommands.ShouldBeNull();
        await using var listener = await StartListenerAsync();
        (await executing.ExecutedCommand.WaitAsync( _timeout )).Result.ShouldBe( "pong:early" );
        sender.CrisChannel.AcceptedCommands.ShouldNotBeNull().ShouldContain( typeof( IPingCommand ).FullName!.Replace( '+', '.' ) );
    }
}
