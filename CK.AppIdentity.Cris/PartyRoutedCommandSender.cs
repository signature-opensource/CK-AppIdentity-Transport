using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Sends a command to a party of the System that is not a remote, in a <see cref="IPartyRoutedCommand"/>: toward the
/// host of a route, or along an explicit path. The local party is the originating party: the caller party of the command
/// on the destination. The command is serialized here (<see cref="IPartyRoutedCommand.SealedCommand"/>), the
/// <see cref="ICrisCallEnvelopeContributor"/> fill its envelope (the user's proof), the optional
/// <see cref="ICrisRoutedCommandSeal"/> seals it, the
/// <see cref="ICrisOutgoingCommandTransformer"/> are not applied (they prepare a command for the remote that receives it,
/// not for the destination).
/// <para>
/// This fails closed and never throws: no route, an unavailable hop or no answer within the timeout (by default the
/// <see cref="ChannelCrisRemoteDispatcher.Timeout"/>) are <see cref="ICrisResultError"/> results. The timeout bounds the
/// wait for the first hop's advertisement and for the answer; the seal's own lookups (an encryption key) are bounded by
/// their own timeouts. Each hop is given a shorter time (see <see cref="IPartyRoutedCommand.TimeBudget"/>): the error of
/// a hop reaches the origin before it gives up. Never wrap a send in a <c>WaitAsync</c>: it would keep running (with the
/// caller's monitor and services) after the caller gave up.
/// </para>
/// </summary>
public sealed class PartyRoutedCommandSender : ISingletonAutoService
{
    readonly PocoDirectory _pocoDirectory;
    readonly IEnumerable<ICrisCallEnvelopeContributor> _contributors;
    readonly ICrisRoutedCommandSeal? _seal;

    /// <summary>
    /// Initializes a new sender.
    /// </summary>
    /// <param name="pocoDirectory">The poco directory.</param>
    /// <param name="contributors">The contributors to the envelope.</param>
    /// <param name="seal">The optional seal of the routed commands.</param>
    public PartyRoutedCommandSender( PocoDirectory pocoDirectory, IEnumerable<ICrisCallEnvelopeContributor> contributors, ICrisRoutedCommandSeal? seal = null )
    {
        _pocoDirectory = pocoDirectory;
        _contributors = contributors;
        _seal = seal;
    }

    /// <summary>
    /// Sends a command to a party along a route of the <paramref name="origin"/> (see <see cref="PartyDescription.Routes"/>)
    /// that this party hosts. Any party of the System can announce a route: when the route of the origin or of a hop leads
    /// to another party, the command is refused, never delivered to that party.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope (for the envelope contributors).</param>
    /// <param name="origin">The originating local party.</param>
    /// <param name="command">The command to execute on the destination.</param>
    /// <param name="routeName">The route name.</param>
    /// <param name="destination">The full name of the party that must host the route: the destination.</param>
    /// <param name="timeout">The maximal time to wait. Defaults to the <see cref="ChannelCrisRemoteDispatcher.Timeout"/>.</param>
    /// <returns>The result of the command, or a <see cref="ICrisResultError"/>.</returns>
    public Task<object?> SendAsync( IActivityMonitor monitor,
                                    IServiceProvider services,
                                    ILocalParty origin,
                                    IAbstractCommand command,
                                    string routeName,
                                    string destination,
                                    TimeSpan? timeout = null )
    {
        Throw.CheckNotNullOrWhiteSpaceArgument( routeName );
        Throw.CheckNotNullOrWhiteSpaceArgument( destination );
        return DoSendAsync( monitor, services, origin, command, r => { r.RouteName = routeName; r.Destination = destination; }, timeout );
    }

    /// <summary>
    /// Sends a command along an explicit path: for an answer, the way back to the party a request came from.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope (for the envelope contributors).</param>
    /// <param name="origin">The originating local party: the first of the path.</param>
    /// <param name="command">The command to execute on the last party of the path.</param>
    /// <param name="path">The full names of the parties, from the origin to the destination.</param>
    /// <param name="timeout">The maximal time to wait. Defaults to the <see cref="ChannelCrisRemoteDispatcher.Timeout"/>.</param>
    /// <returns>The result of the command, or a <see cref="ICrisResultError"/>.</returns>
    public Task<object?> SendAlongPathAsync( IActivityMonitor monitor,
                                             IServiceProvider services,
                                             ILocalParty origin,
                                             IAbstractCommand command,
                                             IEnumerable<string> path,
                                             TimeSpan? timeout = null )
    {
        Throw.CheckNotNullArgument( path );
        return DoSendAsync( monitor, services, origin, command, r => r.Path.AddRange( path ), timeout );
    }

    async Task<object?> DoSendAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty origin, IAbstractCommand command, Action<IPartyRoutedCommand> address, TimeSpan? timeout )
    {
        Throw.CheckNotNullArgument( monitor );
        Throw.CheckNotNullArgument( services );
        Throw.CheckNotNullArgument( origin );
        Throw.CheckNotNullArgument( command );
        Throw.CheckArgument( timeout == null || timeout.Value > TimeSpan.Zero );
        var budget = timeout ?? ChannelCrisRemoteDispatcher.Timeout;
        var start = Stopwatch.GetTimestamp();
        Throw.CheckArgument( "A routed command never carries another one.", command is not IPartyRoutedCommand );
        var routed = _pocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.SealedCommand = CrisChannelFeature.Seal( _pocoDirectory, command );
            address( r );
        } );
        if( !CrisChannelFeature.TryGetNextHop( origin, routed, out var next, out var error ) )
        {
            return Error( monitor, $"Unable to route '{command.CrisPocoModel.PocoName}' from '{origin.FullName}': {error}" );
        }
        if( next == null )
        {
            return Error( monitor, $"Unable to route '{command.CrisPocoModel.PocoName}': its destination is '{origin.FullName}' itself." );
        }
        var (channel, channelError) = await CrisChannelFeature.GetNextChannelAsync( origin, next, CrisChannelFeature.Remaining( start, budget ) ).ConfigureAwait( false );
        if( channel == null )
        {
            return Error( monitor, $"Unable to route '{command.CrisPocoModel.PocoName}' from '{origin.FullName}': {channelError}" );
        }
        routed.Via.Add( origin.FullName );
        routed.TargetPartyFullName = next;
        var envelope = _pocoDirectory.Create<ICrisCallEnvelope>();
        foreach( var c in _contributors )
        {
            c.Contribute( monitor, services, channel.Party, command, routed, envelope );
        }
        object? resultState = null;
        if( _seal != null )
        {
            // The destination: the last party of the path, or the expected host of the route (checked by TryGetNextHop).
            var destination = routed.Path.Count > 0 ? routed.Path[^1] : routed.Destination!;
            (bool success, resultState) = await _seal.SealAsync( monitor, services, origin, destination, command, routed, envelope ).ConfigureAwait( false );
            if( !success )
            {
                return Error( monitor, $"Unable to seal '{command.CrisPocoModel.PocoName}' routed from '{origin.FullName}' to '{destination}'." );
            }
        }
        var remaining = CrisChannelFeature.Remaining( start, budget );
        if( remaining == TimeSpan.Zero )
        {
            return Error( monitor, $"Unable to route '{command.CrisPocoModel.PocoName}' from '{origin.FullName}': no time is left within {budget}." );
        }
        routed.TimeBudget = remaining - CrisChannelFeature.HopMargin;
        monitor.Info( $"Sending '{command.CrisPocoModel.PocoName}' routed from '{origin.FullName}' to '{next}'." );
        // On timeout, the channel abandons the command: its result is a "Cris.Timeout" error.
        var executed = await channel.SendCommand( monitor, routed, envelope: envelope, timeout: remaining ).ExecutedCommand.ConfigureAwait( false );
        if( resultState == null ) return executed.Result;
        return UnsealResult( monitor, channel, command, resultState, executed.Result );
    }

    // The result of a command whose result is sealed: an error made on the way (by a hop, or before the execution) is not
    // sealed and is returned as is; any other result must be sealed by the destination.
    object? UnsealResult( IActivityMonitor monitor, CrisChannelFeature channel, IAbstractCommand command, object resultState, object? result )
    {
        Throw.DebugAssert( _seal != null );
        if( result is ICrisResultError ) return result;
        if( result is not IPartySealedResult sealedResult )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The result of '{command.CrisPocoModel.PocoName}' is not sealed by its destination: it is refused." );
            return Error( monitor, $"The result of '{command.CrisPocoModel.PocoName}' is not sealed by its destination." );
        }
        var bytes = _seal.UnsealResult( monitor, resultState, sealedResult.Sealed );
        var callResult = bytes != null ? channel.ReadResult( monitor, bytes ) : null;
        if( callResult == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The sealed result of '{command.CrisPocoModel.PocoName}' can't be unsealed: it is refused." );
            return Error( monitor, $"The sealed result of '{command.CrisPocoModel.PocoName}' can't be unsealed." );
        }
        return callResult.Result;
    }

    ICrisResultError Error( IActivityMonitor monitor, string text )
    {
        monitor.Error( text );
        return _pocoDirectory.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, "Cris.NoRoute" ) ) );
    }
}
