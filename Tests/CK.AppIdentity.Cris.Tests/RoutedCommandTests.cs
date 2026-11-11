using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
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
        public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, IPartyRoutedCommand? routed, ICrisCallEnvelope envelope )
        {
            if( routed != null ) ((ReceptionTests.ITestEnvelope)envelope).CultureName = "fr";
        }
    }

    // On a hop: the envelope of a forwarded routed command is filtered before it is relayed.
    public sealed class ForwardFilter : ICrisForwardedEnvelopeFilter
    {
        public static readonly ConcurrentQueue<string> Forwarded = new();

        public ValueTask FilterAsync( IActivityMonitor monitor, IRemoteParty sender, IRemoteParty target, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
        {
            var e = (ReceptionTests.ITestEnvelope)envelope;
            Forwarded.Enqueue( $"{e.CultureName} from {sender.FullName} to {target.FullName}" );
            if( e.CultureName != null ) e.CultureName = "en";
            return ValueTask.CompletedTask;
        }
    }

    // Seals at the origin (it marks the envelope with the destination), unseals at the destination (or refuses).
    public sealed class TestSeal : ICrisRoutedCommandSeal
    {
        public static readonly ConcurrentQueue<string> Sealed = new();
        public static readonly ConcurrentQueue<string> Unsealed = new();
        public static readonly ConcurrentQueue<string> Results = new();
        public static volatile bool Refuse;

        public ValueTask<(bool, object?)> SealAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty origin, string destination, IAbstractCommand command, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
        {
            Sealed.Enqueue( $"{command.CrisPocoModel.PocoName.Split( '.' )[^1]} from {origin.FullName} to {destination}" );
            ((ReceptionTests.ITestEnvelope)envelope).CultureName = "sealed";
            // The state of the origin: what unseals the result.
            return ValueTask.FromResult<(bool, object?)>( (true, (byte)0x5A) );
        }

        public ValueTask<(byte[]?, object?)> UnsealAsync( IActivityMonitor monitor, IRemoteParty sender, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
        {
            Unsealed.Enqueue( $"{((ReceptionTests.ITestEnvelope)envelope).CultureName} on {sender.Owner.FullName}" );
            return ValueTask.FromResult<(byte[]?, object?)>( Refuse ? (null, null) : (routed.SealedCommand, (byte)0x5A) );
        }

        // A reversible transform: the hops relay bytes that are not the JSON of the result.
        public byte[] SealResult( object resultState, ReadOnlySpan<byte> result )
        {
            Results.Enqueue( "sealed" );
            return Transform( (byte)resultState, result );
        }

        public byte[]? UnsealResult( IActivityMonitor monitor, object resultState, ReadOnlySpan<byte> sealedResult )
        {
            Results.Enqueue( "unsealed" );
            return Transform( (byte)resultState, sealedResult );
        }

        static byte[] Transform( byte key, ReadOnlySpan<byte> data )
        {
            var r = data.ToArray();
            for( int i = 0; i < r.Length; ++i ) r[i] ^= key;
            return r;
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
                                      typeof( PartyRoutedCommandSender ),
                                      typeof( RecordingReceptionHandler ),
                                      typeof( CurrentLocalParty ),
                                      typeof( CurrentLocalPartyDefaultProvider ),
                                      typeof( ChannelCrisRemoteDispatcher ),
                                      typeof( CrisBackgroundExecutorService ),
                                      typeof( RawCrisReceiver ),
                                      typeof( IWhereRoutedCommand ),
                                      typeof( ReceptionTests.ITestEnvelope ),
                                      typeof( IPartySealedResult )];

    // Like the PartyRoutedCommandSender: the JSON of the command with its type, with the exchange options of the channels.
    static byte[] Serialize( RunningApplication app, IAbstractCommand command )
    {
        var w = new System.Buffers.ArrayBufferWriter<byte>();
        app.PocoDirectory.WriteJson( w, command, withType: true, new PocoJsonExportOptions( PocoJsonExportOptions.ToStringDefault ) { TypeFilterName = "AllExchangeable" } );
        return w.WrittenSpan.ToArray();
    }

    [Test]
    public async Task the_destination_executes_the_command_read_from_the_bytes_of_the_origin_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: _common,
                                                                         listenerTypes: [.. _common, typeof( WhereRoutedHandler )] );
        var (a, b) = pair;
        (await a.CrisChannel.WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;

        var routed = a.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.SealedCommand = Serialize( a, a.PocoDirectory.Create<IWhereRoutedCommand>() );
            r.Path.AddRange( [aName, bName] );
            r.Via.Add( aName );
            r.TargetPartyFullName = bName;
        } );
        var executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, routed ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBe( bName );

        // Bytes that are not a command are refused.
        routed.SealedCommand = [1, 2, 3];
        executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, routed ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "its command cannot be read" );
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
        a.ApplicationIdentityService.Description.Routes["Routed"].ShouldHaveSingleItem().ShouldBe( new PartyRoute( "IWhereRoutedCommand", [aName, bName, cName] ) );

        // By route: executed on its host, the caller party is the origin, the envelope (the user's proof) is relayed.
        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
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
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Unknown", cName ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "has no route 'Unknown'" );

        // A path that doesn't lead to the receiver.
        r = await SendAsync( a, ( s, sp ) => s.SendAlongPathAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), [bName, cName] ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "doesn't lead to" );
    }

    [Test]
    public async Task the_error_of_a_hop_reaches_the_origin_before_it_gives_up_Async()
    {
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: _common,
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: _common );
        var (a, b) = pair;
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        string cName;
        await using( var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                   isSender: true,
                                                                   c => c["FullName"] = "Test/$C",
                                                                   null,
                                                                   [.. _common, typeof( WhereRoutedHandler )] ) )
        {
            cName = c.ApplicationIdentityService.FullName;
            var toC = b.ApplicationIdentityService.Remotes.Single( r => r.FullName == cName ).GetRequiredFeature<CrisChannelFeature>();
            (await toC.WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
            (await a.CrisChannel.WaitForAcceptedCommandsAsync( _timeout )).ShouldBeTrue();
        }
        // C is gone: the hop waits for its answer less long than the origin, its precise error comes back.
        var r = await SendAsync( a, ( s, sp ) => s.SendAlongPathAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), [aName, bName, cName], TimeSpan.FromSeconds( 3 ) ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( $"'{cName}' did not answer" );
    }

    [Test]
    public async Task a_route_name_can_have_several_hosts_each_one_is_reached_by_its_name_Async()
    {
        RecordingReceptionHandler.Callers.Clear();
        // The listener and C both host the route "Routed" (no authority: the routes are believed as announced).
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( WhereRoutedHandler )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver )] );
        var (a, b) = pair;
        await using var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$C",
                                                                  null,
                                                                  [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver )] );
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;
        for( int i = 0; i < 100 && a.ApplicationIdentityService.Description.FindRoute( "Routed", cName ) == null; ++i ) await Task.Delay( 100 );
        a.ApplicationIdentityService.Description.Routes["Routed"].Select( r => r.Host ).ShouldBe( new[] { bName, cName }.Order( StringComparer.Ordinal ) );

        // Each host is reached by its name.
        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
        r.ShouldBe( cName );
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", bName ) );
        r.ShouldBe( bName );

        // Never to whoever hosts the route: the origin refuses another destination...
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", "Test/$Other/#Dev" ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "doesn't lead to 'Test/$Other/#Dev'" );

        // ...and so does a hop.
        RecordingReceptionHandler.Callers.Clear();
        var routed = a.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.SealedCommand = Serialize( a, a.PocoDirectory.Create<IWhereRoutedCommand>() );
            r.RouteName = "Routed";
            r.Destination = "Test/$Other/#Dev";
            r.Via.Add( aName );
            r.TargetPartyFullName = bName;
        } );
        var executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, routed ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "doesn't lead to 'Test/$Other/#Dev'" );

        // A route name without a destination is refused.
        routed.Destination = null;
        executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, routed ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "needs a RouteName and a Destination" );
        RecordingReceptionHandler.Callers.ShouldBeEmpty();
    }

    [Test]
    public async Task a_route_to_a_host_that_is_not_authorized_is_refused_Async()
    {
        // The sender authorizes only C for "Routed" (with its target): the listener's own route is refused, C's route through it is kept.
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderConfiguration: c => c["Local:RouteHosts:Routed:Test/$C/#Dev"] = "IWhereRoutedCommand",
                                                                         senderTypes: [.. _common, typeof( WhereRoutedHandler )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver )] );
        var (a, b) = pair;
        await using var c = await RunningApplication.CreateAsync( TestHelper.Monitor,
                                                                  isSender: true,
                                                                  c => c["FullName"] = "Test/$C",
                                                                  null,
                                                                  [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver )] );
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;
        cName.ShouldBe( "Test/$C/#Dev" );
        (await WaitForRouteAsync( a.ApplicationIdentityService, "Routed" )).ShouldBeTrue();
        a.ApplicationIdentityService.Description.Routes["Routed"].ShouldHaveSingleItem().Host.ShouldBe( cName );

        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
        r.ShouldBe( cName );
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", bName ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( $"doesn't lead to '{bName}'" );
    }

    [Test]
    public async Task the_routed_command_is_sealed_at_its_origin_and_unsealed_at_its_destination_Async()
    {
        RecordingReceptionHandler.Callers.Clear();
        TestSeal.Sealed.Clear();
        TestSeal.Unsealed.Clear();
        TestSeal.Results.Clear();
        TestSeal.Refuse = false;
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( WhereRoutedHandler ), typeof( TestSeal )],
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
                                                                  [.. _common, typeof( WhereRoutedHandler ), typeof( RouteHostFeatureDriver ), typeof( TestSeal )] );
        string aName = a.ApplicationIdentityService.FullName;
        string bName = b.ApplicationIdentityService.FullName;
        string cName = c.ApplicationIdentityService.FullName;
        (await WaitForRouteAsync( a.ApplicationIdentityService, "Routed" )).ShouldBeTrue();

        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
        r.ShouldBe( cName );
        // Sealed for its destination (the host of the route), unsealed by it, before its execution.
        TestSeal.Sealed.ShouldContain( $"IWhereRoutedCommand from {aName} to {cName}" );
        TestSeal.Unsealed.ShouldContain( $"sealed on {cName}" );
        RecordingReceptionHandler.Callers.ShouldContain( $"IWhereRoutedCommand from {aName} (via {bName}) [sealed]" );
        // The result has been sealed by the destination, unsealed by the origin.
        TestSeal.Results.ShouldBe( ["sealed", "unsealed"] );

        // The destination refuses to unseal it.
        TestSeal.Refuse = true;
        r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
        r.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "its command cannot be unsealed" );
        TestSeal.Refuse = false;
    }

    [Test]
    public async Task a_hop_filters_the_envelope_it_forwards_Async()
    {
        RecordingReceptionHandler.Callers.Clear();
        ForwardFilter.Forwarded.Clear();
        await using var pair = await RunningApplication.CreatePairAsync( TestHelper.Monitor,
                                                                         senderTypes: [.. _common, typeof( WhereRoutedHandler ), typeof( RoutedEnvelopeContributor )],
                                                                         listenerConfiguration: c =>
                                                                         {
                                                                             c["Parties:1:PartyName"] = "$C";
                                                                             c["Parties:1:AutoTrustKey"] = "Once";
                                                                         },
                                                                         listenerTypes: [.. _common, typeof( ForwardFilter )] );
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

        var r = await SendAsync( a, ( s, sp ) => s.SendAsync( TestHelper.Monitor, sp, a.ApplicationIdentityService, a.PocoDirectory.Create<IWhereRoutedCommand>(), "Routed", cName ) );
        r.ShouldBe( cName );
        // The hop saw the origin's envelope, the destination received the filtered one.
        ForwardFilter.Forwarded.ShouldContain( $"fr from {aName} to {cName}" );
        RecordingReceptionHandler.Callers.ShouldContain( $"IWhereRoutedCommand from {aName} (via {bName}) [en]" );
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
            r.SealedCommand = Serialize( a, a.PocoDirectory.Create<IWhereRoutedCommand>() );
            r.Path.AddRange( ["Test/$Evil", bName] );
            r.Via.Add( "Test/$Evil" );
            r.TargetPartyFullName = bName;
        } );
        var executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, forged ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "not the remote that sent it" );

        // A routed command never carries another one.
        var nested = a.PocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.SealedCommand = Serialize( a, a.PocoDirectory.Create<IPartyRoutedCommand>() );
            r.Path.AddRange( [(string)a.ApplicationIdentityService.FullName, bName] );
            r.Via.Add( a.ApplicationIdentityService.FullName );
            r.TargetPartyFullName = bName;
        } );
        executed = await a.CrisChannel.SendCommand( TestHelper.Monitor, nested ).ExecutedCommand.WaitAsync( _timeout );
        executed.Result.ShouldBeAssignableTo<ICrisResultError>()!.Errors.Single().Text.ShouldContain( "another routed command" );
    }
}
