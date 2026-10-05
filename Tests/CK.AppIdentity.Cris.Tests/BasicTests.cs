using CK.Auth;
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

public class BasicTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    [Test]
    public async Task basic_sending_and_receiving_Async()
    {
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null );

        // Checks that Listener/Sender are actually different thanks to the handlers.
        sender.Services.GetService<SenderHandler>().ShouldNotBeNull();
        sender.Services.GetService<ListenerHandler>().ShouldBeNull();

        listener.Services.GetService<SenderHandler>().ShouldBeNull();
        listener.Services.GetService<ListenerHandler>().ShouldNotBeNull();

        var sC = sender.PocoDirectory.Create<ISenderCommand>( c => c.Message = "Hello" );
        var executing = sender.CrisChannel.SendCommand( TestHelper.Monitor, sC );
        var result = await executing.WithResult<string>().Result.WaitAsync( _timeout );
        result.ShouldBe( "Listener received 'Hello'." );

        // The immediate event emitted by the remote handler is received before the result.
        executing.ImmediateEvents.Count.ShouldBe( 1 );
        var executed = await executing.ExecutedCommand;
        executed.Command.ShouldBeSameAs( sC );
        executed.Events.ShouldBeEmpty();
    }

    [Test]
    public async Task commands_flow_in_both_directions_Async()
    {
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null );

        var sC = sender.PocoDirectory.Create<ISenderCommand>( c => c.Message = "From sender" );
        (await sender.CrisChannel.SendCommand( TestHelper.Monitor, sC ).WithResult<string>().Result.WaitAsync( _timeout ))
            .ShouldBe( "Listener received 'From sender'." );

        var lC = listener.PocoDirectory.Create<IListenerCommand>( c => c.Message = "From listener" );
        (await listener.CrisChannel.SendCommand( TestHelper.Monitor, lC ).WithResult<string>().Result.WaitAsync( _timeout ))
            .ShouldBe( "Sender received 'From listener'." );
    }

    [Test]
    public async Task a_command_sent_before_the_remote_exists_is_executed_once_connected_Async()
    {
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        var sC = sender.PocoDirectory.Create<ISenderCommand>( c => c.Message = "Early" );
        var executing = sender.CrisChannel.SendCommand( TestHelper.Monitor, sC );
        await Task.Delay( 200 );
        executing.ExecutedCommand.IsCompleted.ShouldBeFalse();

        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null );
        (await executing.WithResult<string>().Result.WaitAsync( _timeout )).ShouldBe( "Listener received 'Early'." );
    }

    [Test]
    public async Task a_command_without_handler_on_the_remote_returns_an_error_Async()
    {
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null );

        // The Sender has no handler for its own ISenderCommand.
        var sC = listener.PocoDirectory.Create<ISenderCommand>( c => c.Message = "Nobody handles this" );
        var executing = listener.CrisChannel.SendCommand( TestHelper.Monitor, sC );
        var executed = await executing.ExecutedCommand.WaitAsync( _timeout );
        var error = executed.Result.ShouldBeAssignableTo<ICrisResultError>();
        error.ShouldNotBeNull().Errors.ShouldNotBeEmpty();
        await Should.ThrowAsync<CKException>( executing.WithResult<string>().Result );
    }

    [Test]
    public async Task the_remote_executes_as_the_authenticated_party_and_anonymous_user_Async()
    {
        // StdAuthenticationInfo makes IAuthenticationInfo an (ambient) service of the applications.
        await using var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null, typeof( StdAuthenticationInfo ) );
        await using var listener = await RunningApplication.CreateAsync( TestHelper.Monitor, false, null, null, typeof( StdAuthenticationInfo ) );

        // Nothing in the message can carry a user identity: the only identity established is
        // the one of the remote party itself (authenticated by the transport).
        var who = sender.PocoDirectory.Create<IWhoAmICommand>();
        var result = await sender.CrisChannel.SendCommand( TestHelper.Monitor, who ).WithResult<string>().Result.WaitAsync( _timeout );
        // The calling party, and the anonymous user (empty user name).
        result.ShouldBe( "Test/$Sender/#Dev/" );
    }

    [Test]
    public async Task pending_commands_are_failed_when_the_application_stops_Async()
    {
        var sender = await RunningApplication.CreateAsync( TestHelper.Monitor, true, null, null );
        var sC = sender.PocoDirectory.Create<ISenderCommand>( c => c.Message = "Never sent" );
        var executing = sender.CrisChannel.SendCommand( TestHelper.Monitor, sC );
        await sender.DisposeAsync();
        var executed = await executing.ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()
                       .ShouldNotBeNull().Errors.Single().Text.ShouldContain( "is no more available" );
    }
}
