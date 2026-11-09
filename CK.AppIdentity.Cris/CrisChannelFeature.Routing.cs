using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public sealed partial class CrisChannelFeature
{
    /// <summary>
    /// Handles a <see cref="IPartyRoutedCommand"/> received from the remote (it is accepted and targets this party): checks
    /// its chain, then forwards it to its next hop, or returns its inner command when this party is the destination.
    /// </summary>
    /// <returns>The inner command to execute here, or null (forwarded, or refused: an error has been sent).</returns>
    internal IAbstractCommand? HandleRouted( IActivityMonitor monitor, Protocol handler, ActivityMonitor.Token token, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        var local = Party.Owner;
        string? next = null;
        var error = CheckChain( Party, routed );
        if( error == null ) TryGetNextHop( local, routed, out next, out error );
        if( error != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Routed command received from '{Party.FullName}' is refused: {error}" );
            handler.SendError( monitor, token.Key, $"The routed command is refused: {error}" );
            return null;
        }
        var inner = routed.Command;
        Throw.DebugAssert( inner != null );
        if( next != null )
        {
            routed.Via.Add( local.FullName );
            routed.TargetPartyFullName = next;
            monitor.Info( $"Forwarding '{inner.CrisPocoModel.PocoName}' routed from '{routed.Via[0]}' to '{next}'." );
            _ = ForwardAsync( handler, token, routed, envelope, next );
            return null;
        }
        // This is the destination.
        string? refused = null;
        var m = inner.CrisPocoModel;
        if( _receptionHandler == null ) refused = "this party has no reception handler (it cannot establish the identity of a routed command)";
        else if( !m.IsHandled || m.Exposure == CrisExposure.Private ) refused = $"command '{m.PocoName}' is not handled here";
        else if( inner is ICommandEndpointOnly ) refused = $"command '{m.PocoName}' is endpoint-only";
        else if( inner is ICommandTargetParty p && p.TargetPartyFullName != local.FullName ) refused = $"party command '{m.PocoName}' doesn't target '{local.FullName}'";
        if( refused != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Command routed from '{routed.Via[0]}' is refused: {refused}." );
            handler.SendError( monitor, token.Key, $"The routed command is refused: {refused}." );
            return null;
        }
        monitor.Info( $"Executing '{m.PocoName}' routed from '{routed.Via[0]}' (via {string.Join( " > ", routed.Via )})." );
        return inner;
    }

    // Each hop vouches for its predecessor only: the last of Via is the sender. No loop, no nesting.
    static string? CheckChain( IRemoteParty sender, IPartyRoutedCommand routed )
    {
        var local = sender.Owner;
        if( routed.Command == null ) return "it has no command.";
        if( routed.Command is IPartyRoutedCommand ) return "it carries another routed command.";
        if( routed.Via.Count == 0 ) return "its Via is empty.";
        var last = routed.Via[^1];
        if( last != sender.FullName.Path )
        {
            return $"its last hop is '{last}', not the remote that sent it ('{sender.FullName}').";
        }
        if( routed.Via.Count >= PartyRoute.MaxLength ) return $"it went through {routed.Via.Count} parties.";
        if( routed.Via.Distinct( StringComparer.Ordinal ).Count() != routed.Via.Count
            || routed.Via.Any( h => h == local.FullName.Path ) )
        {
            return "its Via contains a loop.";
        }
        return null;
    }

    /// <summary>
    /// Gets the next hop of a routed command on a local party (the routed command's <see cref="IPartyRoutedCommand.Via"/>
    /// doesn't contain it yet): its route of the <see cref="IPartyRoutedCommand.RouteName"/>, or the party after it in the
    /// <see cref="IPartyRoutedCommand.Path"/>.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <param name="routed">The routed command.</param>
    /// <param name="next">The full name of the next hop, or null when the local party is the destination.</param>
    /// <param name="error">The reason why there is no next hop.</param>
    /// <returns>True on success, false on error.</returns>
    internal static bool TryGetNextHop( ILocalParty local, IPartyRoutedCommand routed, out string? next, out string? error )
    {
        next = null;
        error = null;
        if( (routed.RouteName == null) == (routed.Path.Count == 0) )
        {
            error = "it needs a RouteName or a Path (not both).";
            return false;
        }
        if( routed.RouteName != null )
        {
            if( !local.Description.Routes.TryGetValue( routed.RouteName, out var route ) )
            {
                error = $"'{local.FullName}' has no route '{routed.RouteName}'.";
                return false;
            }
            next = route.NextHop;
            return true;
        }
        int i = routed.Via.Count;
        if( i >= routed.Path.Count
            || routed.Path[i] != local.FullName
            || !routed.Via.SequenceEqual( routed.Path.Take( i ), StringComparer.Ordinal ) )
        {
            error = $"its path '{string.Join( " > ", routed.Path )}' doesn't lead to '{local.FullName}' after '{string.Join( " > ", routed.Via )}'.";
            return false;
        }
        next = i + 1 < routed.Path.Count ? routed.Path[i + 1] : null;
        return true;
    }

    /// <summary>
    /// Gets the channel to a remote of a local party that accepts the routed commands, or null with an error.
    /// </summary>
    internal static async Task<(CrisChannelFeature? Channel, string? Error)> GetNextChannelAsync( ILocalParty local, string next )
    {
        var channel = local.Remotes.FirstOrDefault( r => r.FullName == next )?.GetFeature<CrisChannelFeature>();
        if( channel == null || !channel.IsRemoteInsideSystem ) return (null, $"'{next}' is not a remote of '{local.FullName}' inside the System.");
        if( !await channel.WaitForAcceptedCommandsAsync( ChannelCrisRemoteDispatcher.Timeout ).ConfigureAwait( false ) )
        {
            return (null, $"Party '{next}' is not available.");
        }
        var name = channel._crisDirectory.CrisPocoModels.First( m => typeof( IPartyRoutedCommand ).IsAssignableFrom( m.CommandType ) ).PocoName;
        if( channel.AcceptedCommands?.Contains( name ) is not true ) return (null, $"Party '{next}' doesn't accept routed commands.");
        return (channel, null);
    }

    // Forwards the routed command and sends its answers back to the remote that sent it: the received envelope (and the
    // user's proof it may carry) travels unchanged.
    async Task ForwardAsync( Protocol handler, ActivityMonitor.Token token, IPartyRoutedCommand routed, ICrisCallEnvelope envelope, string next )
    {
        var monitor = new ActivityMonitor( $"Forwarding a routed command from '{Party.FullName}' to '{next}'." );
        try
        {
            var (channel, error) = await GetNextChannelAsync( Party.Owner, next ).ConfigureAwait( false );
            if( channel == null )
            {
                monitor.Warn( error! );
                handler.SendError( monitor, token.Key, error! );
                return;
            }
            var executing = channel.SendCommand( monitor, routed, envelope: envelope );
            executing.ImmediateEvents.Added.Async += ( m, e, cancel ) =>
            {
                handler.SendImmediateEvent( m, token.Key, e );
                return Task.CompletedTask;
            };
            IExecutedCommand executed;
            try
            {
                executed = await executing.ExecutedCommand.WaitAsync( ChannelCrisRemoteDispatcher.Timeout ).ConfigureAwait( false );
            }
            catch( TimeoutException )
            {
                handler.SendError( monitor, token.Key, $"Party '{next}' did not answer within {ChannelCrisRemoteDispatcher.Timeout}." );
                return;
            }
            foreach( var e in executed.Events ) handler.SendFinalEvent( monitor, token.Key, e );
            handler.SendExecuted( monitor, token.Key, executed.Result, executed.ValidationMessages );
        }
        catch( Exception ex )
        {
            monitor.Error( ex );
            handler.SendError( monitor, token.Key, "Unable to forward the routed command." );
        }
        finally
        {
            monitor.MonitorEnd();
        }
    }
}
