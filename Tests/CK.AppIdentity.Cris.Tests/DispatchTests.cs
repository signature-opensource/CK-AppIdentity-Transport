using CK.Core;
using CK.Cris;
using CK.Monitoring;
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

    // Local events: never sent by a remote (they are dispatched where the command executes).
    [LocalEvent]
    public interface ILocalPongEvent : IEvent
    {
    }

    [LocalEvent, ImmediateEvent]
    public interface ILocalImmediatePongEvent : IEvent
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

    // Endpoint-only (like a login command): executed by the endpoint that receives it, never dispatched.
    public interface IEndpointOnlyCommand : ICommand<string>, ICommandEndpointOnly
    {
    }

    // Dispatched: handled by the senders only.
    public interface ISendersCommand : ICommand<string>
    {
    }

    // The handlers of the two senders of the deployment check test.
    public sealed class SendersSide : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IEndpointOnlyCommand c ) => "endpoint-only";

        [CommandHandler]
        public string Handle( ISendersCommand c ) => "senders";
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
                                      typeof( IEndpointOnlyCommand ),
                                      typeof( ISendersCommand ),
                                      typeof( IPongEvent ),
                                      typeof( IPongImmediateEvent ),
                                      typeof( ILocalPongEvent ),
                                      typeof( ILocalImmediatePongEvent ),
                                      typeof( BothSides ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( CommandTargetPartyValidator )];

    // A sender started before its listener needs a heart beat: it retries its connection.
    static Task<RunningApplication> StartSenderAsync( bool withHeartBeat )
        => RunningApplication.CreateAsync( TestHelper.Monitor, true, null, withHeartBeat ? RunningApplication.WithHeartBeat() : null, _common );

    static Task<RunningApplication> StartListenerAsync()
        => RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null, [.. _common, typeof( ListenerSide )] );

    // The listener first: the sender connects at once.
    static Task<RunningApplicationPair> StartPairAsync( Action<MutableConfigurationSection>? senderConfiguration = null,
                                                        Action<MutableConfigurationSection>? listenerConfiguration = null )
        => RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                               senderConfiguration, _common,
                                               listenerConfiguration, [.. _common, typeof( ListenerSide )] );

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
        await using var pair = await StartPairAsync();
        var (sender, listener) = pair;

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
    public async Task only_the_caller_only_events_are_accepted_from_a_remote_Async()
    {
        // No listener: the commands stay pending, the "answers" of the remote are simulated.
        await using var sender = await StartSenderAsync( withHeartBeat: false );
        var channel = sender.CrisChannel;

        // A caller-only immediate event is accepted.
        var executing = channel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IPingCommand>() );
        await channel.OnImmediateEventAsync( TestHelper.Monitor, executing.IssuerToken.Key, sender.PocoDirectory.Create<IPongImmediateEvent>() );
        executing.ImmediateEvents.ShouldHaveSingleItem().ShouldBeAssignableTo<IPongImmediateEvent>();
        executing.ExecutedCommand.IsCompleted.ShouldBeFalse();

        // A local immediate event is refused: the command fails.
        executing = channel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IPingCommand>() );
        await channel.OnImmediateEventAsync( TestHelper.Monitor, executing.IssuerToken.Key, sender.PocoDirectory.Create<ILocalImmediatePongEvent>() );
        executing.ImmediateEvents.ShouldBeEmpty();
        (await executing.ExecutedCommand.WaitAsync( _timeout )).Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "not caller-only" );

        // A local final event too.
        executing = channel.SendCommand( TestHelper.Monitor, sender.PocoDirectory.Create<IPingCommand>() );
        channel.OnFinalEvent( TestHelper.Monitor, executing.IssuerToken.Key, sender.PocoDirectory.Create<ILocalPongEvent>() );
        var executed = await executing.ExecutedCommand.WaitAsync( _timeout );
        executed.Events.ShouldBeEmpty();
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "not caller-only" );
    }

    [Test]
    public async Task a_party_command_executes_where_its_target_is_Async()
    {
        // The sender has a tenant domain (its party name is its domain name).
        await using var pair = await StartPairAsync( c => c["Parties:1:FullName"] = "Tenant/$Tenant" );
        var (sender, listener) = pair;
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
        await using var pair = await StartPairAsync( c =>
        {
            c["FullName"] = "Other/$Sender";
            c["Parties:0:PartyName"] = null;
            c["Parties:0:FullName"] = "Test/$Listener";
        }, c =>
        {
            c["Parties:0:PartyName"] = null;
            c["Parties:0:FullName"] = "Other/$Sender";
        } );
        var (sender, listener) = pair;

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
        await using var sender = await StartSenderAsync( withHeartBeat: true );
        // The listener doesn't exist yet: the dispatch waits for its advertisement (up to the timeout).
        var executing = Submit( sender, sender.PocoDirectory.Create<IPingCommand>( c => c.Text = "early" ) );
        sender.CrisChannel.AcceptedCommands.ShouldBeNull();
        await using var listener = await StartListenerAsync();
        (await executing.ExecutedCommand.WaitAsync( _timeout )).Result.ShouldBe( "pong:early" );
        sender.CrisChannel.AcceptedCommands.ShouldNotBeNull().ShouldContain( typeof( IPingCommand ).FullName!.Replace( '+', '.' ) );
    }

    [Test]
    public async Task the_deployment_check_ignores_the_endpoint_only_commands_that_are_never_dispatched_Async()
    {
        using var logs = GrandOutput.Default!.CreateMemoryCollector( 5000 );
        // The listener has two sender remotes that handle both commands (like the Front and the Admin of a Backend that
        // receive the login commands): the listener handles none of them.
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, c =>
        {
            c["Parties:1:PartyName"] = "$Sender2";
            c["Parties:1:AutoTrustKey"] = "Once";
        }, null, _common );
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null, [.. _common, typeof( SendersSide )] );
        await using var sender2 = await RunningApplication.CreateAsync( TestHelper.Monitor, true, c => c["FullName"] = "Test/$Sender2", null, [.. _common, typeof( SendersSide )] );
        foreach( var r in listener.ApplicationIdentityService.Remotes )
        {
            (await r.GetRequiredFeature<CrisChannelFeature>().WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
        }
        // The check runs once the second advertisement is recorded: waits for its (real) error.
        var errors = new System.Collections.Generic.List<string>();
        for( int i = 0; i < 50 && !errors.Any( e => e.Contains( "ISendersCommand" ) ); ++i )
        {
            await Task.Delay( 100 );
            errors.AddRange( logs.ExtractCurrentTexts().Where( t => t.StartsWith( "Deployment error" ) ) );
        }
        await Task.Delay( 200 );
        errors.AddRange( logs.ExtractCurrentTexts().Where( t => t.StartsWith( "Deployment error" ) ) );
        // A command that can be dispatched is ambiguous...
        errors.ShouldContain( e => e.Contains( "ISendersCommand" ) );
        // ...an endpoint-only one is never dispatched.
        errors.ShouldNotContain( e => e.Contains( "IEndpointOnlyCommand" ) );
    }
}
