using CK.Core;
using CK.Cris;
using CK.Testing.AppIdentity.Cris;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.AppIdentity.Cris.Tests;

/// <summary>
/// The <see cref="IPartyRoutedCommand"/>: three parties in a chain, "Test/$Sender" &gt; "Test/$Listener" &lt; "Test/$C"
/// (the sender and C both connect to the listener). C hosts the route "Routed".
/// </summary>
[TestFixture]
public class RoutedCommandTests
{
    static readonly TimeSpan _timeout = TimeSpan.FromSeconds( 30 );

    public interface IWhereRoutedCommand : ICommand<string>
    {
    }

    public sealed class WhereRoutedHandler : ISingletonAutoService
    {
        [CommandHandler]
        public string Handle( IWhereRoutedCommand c, CurrentLocalParty party ) => party.LocalParty.FullName;
    }

    // Records the caller party of the received commands.
    public sealed class RecordingReceptionHandler : ICrisChannelReceptionHandler
    {
        public static readonly ConcurrentQueue<string> Callers = new();

        public ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                                           IServiceProvider services,
                                                                                           CrisCallerParty caller,
                                                                                           IAbstractCommand command,
                                                                                           ICrisCallEnvelope envelope )
        {
            var culture = (envelope as ReceptionTests.ITestEnvelope)?.CultureName;
            Callers.Enqueue( $"{command.CrisPocoModel.PocoName.Split( '.' )[^1]} from {caller}{(culture != null ? $" [{culture}]" : "")}" );
            return ValueTask.FromResult<(ICrisResultError?, AmbientServiceHub?)>( (null, services.GetRequiredService<AmbientServiceHub>().CleanClone()) );
        }
    }

    // On the origin: the envelope of a routed command travels unchanged to the destination.
    public sealed class RoutedEnvelopeContributor : ICrisCallEnvelopeContributor
    {
        public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallEnvelope envelope )
        {
            if( command is IPartyRoutedCommand ) ((ReceptionTests.ITestEnvelope)envelope).CultureName = "fr";
        }
    }

    public sealed class RouteHostFeatureDriver : ApplicationIdentityFeatureDriver
    {
        public RouteHostFeatureDriver( ApplicationIdentityService s ) : base( s, true ) { }

        protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder ) => builder.HostRoute( "Routed", "IWhereRoutedCommand" );

        protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

        protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

        protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

        protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
    }

    static readonly Type[] _common = [typeof( IPartyRoutedCommand ),
                                      typeof( IPartyRouteHop ),
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( RecordingReceptionHandler ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( IWhereRoutedCommand ),
                                      typeof( ReceptionTests.ITestEnvelope )];

    static async Task<bool> WaitForRouteAsync( ILocalParty local, string name )
    {
        for( int i = 0; i < 100; ++i )
        {
            if( local.Description.Routes.ContainsKey( name ) ) return true;
            await Task.Delay( 100 );
        }
        return false;
    }

    static Task<object?> SendAsync( RunningApplication app, Func<PartyRoutedCommandSender, IServiceProvider, Task<object?>> send )
    {
        var scope = app.CreateScopeServices();
        return send( app.Services.GetRequiredService<PartyRoutedCommandSender>(), scope.ServiceProvider ).ContinueWith( t => { scope.Dispose(); return t.Result; } );
    }

    [Test]
    public async Task a_command_is_routed_to_the_host_of_a_route_and_back_along_a_path_Async()
    {
        RecordingReceptionHandler.Callers.Clear();
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( WhereRoutedHandler ), typeof( RoutedEnvelopeContributor )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: _common );
        var (a, b) = pair;
        await using var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$C",
                                                                  null,
                                                                  [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver )] );
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;

        (await WaitForRouteAsync( a.ApplicationIdentityService, "Routed" )).ShouldBeTrue();
        a.ApplicationIdentityService.Description.Routes["Routed"].ShouldBe( new PartyRoute( "IWhereRoutedCommand", [aName, bName, cName] ) );

        // By route: executed on its host, the caller party is the origin, the envelope (the user's proof) is relayed.
        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed" ) );
        r.ShouldBe( cName );
        RecordingReceptionHandler.Callers.ShouldContain( $"IWhereRoutedCommand from {aName} (via {bName}) [fr]" );

        // By path: the way back.
        r = await SendAsync( c, ( s, sp ) => s.SendAlongPathAsync( TestHelper.Monitor, sp, c.ApplicationIdentityService, c.PocoDirectory.Create<IWhereRoutedCommand>(), [cName, bName, aName] ) );
        r.ShouldBe( aName );
        RecordingReceptionHandler.Callers.ShouldContain( $"IWhereRoutedCommand from {cName} (via {bName})" );

        // A destination that doesn't handle the command refuses it.
        r = await SendAsync( a, ( s, sp ) => s.SendAlongPathAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), [aName, bName] ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "is not handled here" );

        // No route.
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Unknown" ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "has no route 'Unknown'" );

        // A path that doesn't lead to the receiver.
        r = await SendAsync( a, ( s, sp ) => s.SendAlongPathAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), [bName, cName] ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "doesn't lead to" );
    }

    [Test]
    public async Task a_hop_vouches_for_its_predecessor_only_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: _common,
                                                                         listenerTypes: [.. _common, typeof( WhereRoutedHandler )] );
        var (a, b) = pair;
        (await a.CrisChannel.WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
        string bName = b.ApplicationIdentityService.FullName;

        // The origin is forged: the last hop is not the remote that sent it.
        var forged = a.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.Command = a.PocoDirectory.Create<IWhereRoutedCommand>();
            r.Path.AddRange( ["Test/$Evil", bName] );
            r.Via.Add( a.PocoDirectory.Create<IPartyRouteHop>( h => h.FullName = "Test/$Evil" ) );
            r.TargetPartyFullName = bName;
        } );
        var executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, forged ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "not the remote that sent it" );

        // A routed command never carries another one.
        var nested = a.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.Command = a.PocoDirectory.Create<IPartyRoutedCommand>();
            r.Path.AddRange( [(string)a.ApplicationIdentityService.FullName, bName] );
            r.Via.Add( a.PocoDirectory.Create<IPartyRouteHop>( h => h.FullName = a.ApplicationIdentityService.FullName ) );
            r.TargetPartyFullName = bName;
        } );
        executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, nested ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "another routed command" );
    }
}
