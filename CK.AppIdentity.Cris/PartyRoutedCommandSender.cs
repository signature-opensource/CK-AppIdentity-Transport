using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Sends a command to a party of the System that is not a remote, in a <see cref="IPartyRoutedCommand"/>: toward the
/// host of a route, or along an explicit path. The local party is the originating party: the caller party of the command
/// on the destination. The <see cref="ICrisCallEnvelopeContributor"/> fill its envelope (the user's proof), the
/// <see cref="ICrisOutgoingCommandTransformer"/> are not applied (they prepare a command for the remote that receives it,
/// not for the destination).
/// <para>
/// This fails closed and never throws: no route, an unavailable hop or no answer within the
/// <see cref="ChannelCrisRemoteDispatcher.Timeout"/> are <see cref="ICrisResultError"/> results.
/// </para>
/// </summary>
public sealed class PartyRoutedCommandSender : ISingletonAutoService
{
    readonly PocoDirectory _pocoDirectory;
    readonly IEnumerable<ICrisCallEnvelopeContributor> _contributors;

    /// <summary>
    /// Initializes a new sender.
    /// </summary>
    /// <param name="pocoDirectory">The poco directory.</param>
    /// <param name="contributors">The contributors to the envelope.</param>
    public PartyRoutedCommandSender( PocoDirectory pocoDirectory, IEnumerable<ICrisCallEnvelopeContributor> contributors )
    {
        _pocoDirectory = pocoDirectory;
        _contributors = contributors;
    }

    /// <summary>
    /// Sends a command to the host of a route of the <paramref name="origin"/> (see <see cref="PartyDescription.Routes"/>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope (for the envelope contributors).</param>
    /// <param name="origin">The originating local party.</param>
    /// <param name="command">The command to execute on the host of the route.</param>
    /// <param name="routeName">The route name.</param>
    /// <returns>The result of the command, or a <see cref="ICrisResultError"/>.</returns>
    public Task<object?> SendAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty origin, IAbstractCommand command, string routeName )
    {
        Throw.CheckNotNullOrWhiteSpaceArgument( routeName );
        return DoSendAsync( monitor, services, origin, command, r => r.RouteName = routeName );
    }

    /// <summary>
    /// Sends a command along an explicit path: for an answer, the way back to the party a request came from.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope (for the envelope contributors).</param>
    /// <param name="origin">The originating local party: the first of the path.</param>
    /// <param name="command">The command to execute on the last party of the path.</param>
    /// <param name="path">The full names of the parties, from the origin to the destination.</param>
    /// <returns>The result of the command, or a <see cref="ICrisResultError"/>.</returns>
    public Task<object?> SendAlongPathAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty origin, IAbstractCommand command, IEnumerable<string> path )
    {
        Throw.CheckNotNullArgument( path );
        return DoSendAsync( monitor, services, origin, command, r => r.Path.AddRange( path ) );
    }

    async Task<object?> DoSendAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty origin, IAbstractCommand command, Action<IPartyRoutedCommand> address )
    {
        Throw.CheckNotNullArgument( monitor );
        Throw.CheckNotNullArgument( services );
        Throw.CheckNotNullArgument( origin );
        Throw.CheckNotNullArgument( command );
        Throw.CheckArgument( "A routed command never carries another one.", command is not IPartyRoutedCommand );
        var routed = _pocoDirectory.Create<IPartyRoutedCommand>( r =>
        {
            r.Command = command;
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
        var (channel, channelError) = await CrisChannelFeature.GetNextChannelAsync( origin, next ).ConfigureAwait( false );
        if( channel == null )
        {
            return Error( monitor, $"Unable to route '{command.CrisPocoModel.PocoName}' from '{origin.FullName}': {channelError}" );
        }
        routed.Via.Add( origin.FullName );
        routed.TargetPartyFullName = next;
        var envelope = _pocoDirectory.Create<ICrisCallEnvelope>();
        foreach( var c in _contributors )
        {
            c.Contribute( monitor, services, channel.Party, routed, envelope );
        }
        monitor.Info( $"Sending '{command.CrisPocoModel.PocoName}' routed from '{origin.FullName}' to '{next}'." );
        try
        {
            var executed = await channel.SendCommand( monitor, routed, envelope: envelope ).ExecutedCommand.WaitAsync( ChannelCrisRemoteDispatcher.Timeout ).ConfigureAwait( false );
            return executed.Result;
        }
        catch( TimeoutException )
        {
            return Error( monitor, $"Party '{next}' did not answer '{command.CrisPocoModel.PocoName}' routed from '{origin.FullName}' within {ChannelCrisRemoteDispatcher.Timeout}." );
        }
    }

    ICrisResultError Error( IActivityMonitor monitor, string text )
    {
        monitor.Error( text );
        return _pocoDirectory.Create<ICrisResultError>( e => e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, "Cris.NoRoute" ) ) );
    }
}
