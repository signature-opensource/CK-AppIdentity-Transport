using CK.Core;
using CK.Cris;
using CK.Poco.Exc.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public sealed partial class CrisChannelFeature
{
    // Applies the incoming transformers to a received command. False when it is refused (an error has been sent).
    internal bool TransformIncoming( IActivityMonitor monitor, Protocol handler, ActivityMonitor.Token token, IAbstractCommand command )
    {
        foreach( var t in _incomingTransformers )
        {
            if( !t.Transform( monitor, Party, command ) )
            {
                handler.SendError( monitor, token.Key, $"Command '{command.CrisPocoModel.PocoName}' is refused." );
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Handles a <see cref="IPartyRoutedCommand"/> received from the remote (it is accepted and targets this party): checks
    /// its chain, then forwards it to its next hop, or receives it when this party is the destination (its command is
    /// unsealed, read, checked and executed). Both run on their own task: an error is sent to the remote.
    /// </summary>
    internal void HandleRouted( IActivityMonitor monitor, Protocol handler, ActivityMonitor.Token token, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        var local = Party.Owner;
        string? next = null;
        var error = CheckChain( Party, routed );
        if( error == null ) TryGetNextHop( local, routed, out next, out error );
        if( error != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Routed command received from '{Party.FullName}' is refused: {error}" );
            handler.SendError( monitor, token.Key, $"The routed command is refused: {error}" );
            return;
        }
        if( next != null )
        {
            routed.Via.Add( local.FullName );
            routed.TargetPartyFullName = next;
            monitor.Info( $"Forwarding a command routed from '{routed.Via[0]}' to '{next}'." );
            _ = ForwardAsync( handler, token, routed, envelope, next );
            return;
        }
        _ = ReceiveRoutedAsync( handler, token, routed, envelope );
    }

    // This is the destination: the command is the one read from the bytes of the origin (unsealed by the seal, if any).
    async Task ReceiveRoutedAsync( Protocol handler, ActivityMonitor.Token token, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        var monitor = new ActivityMonitor( $"Receiving a command routed from '{routed.Via[0]}' on '{Party.Owner.FullName}'." );
        try
        {
            var (inner, resultSealState) = await ReceiveRoutedCommandAsync( monitor, handler, token, routed, envelope ).ConfigureAwait( false );
            if( inner != null && TransformIncoming( monitor, handler, token, inner ) )
            {
                _executor.Execute( handler, inner, token, envelope, routed, resultSealState );
            }
        }
        catch( Exception ex )
        {
            monitor.Error( ex );
            handler.SendError( monitor, token.Key, "Unable to receive the routed command." );
        }
        finally
        {
            monitor.MonitorEnd();
        }
    }

    // Unseals, reads and checks the command of a routed command. Null when it is refused (an error has been sent).
    async Task<(IAbstractCommand? Command, object? ResultSealState)> ReceiveRoutedCommandAsync( IActivityMonitor monitor, Protocol handler, ActivityMonitor.Token token, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        var local = Party.Owner;
        var (bytes, resultSealState) = _routedCommandSeal != null
                                        ? await _routedCommandSeal.UnsealAsync( monitor, Party, routed, envelope ).ConfigureAwait( false )
                                        : (routed.SealedCommand, null);
        var inner = bytes != null ? ReadCommand( monitor, _pocoDirectory, bytes ) : null;
        if( inner == null || inner is IPartyRoutedCommand )
        {
            var reason = bytes == null
                            ? "its command cannot be unsealed"
                            : inner == null ? "its command cannot be read" : "it carries another routed command";
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Routed command received from '{Party.FullName}' is refused: {reason}." );
            handler.SendError( monitor, token.Key, $"The routed command is refused: {reason}." );
            return (null, null);
        }
        string? refused = null;
        var m = inner.CrisPocoModel;
        if( !m.IsHandled || m.Exposure == CrisExposure.Private ) refused = $"command '{m.PocoName}' is not handled here";
        else if( inner is ICommandEndpointOnly ) refused = $"command '{m.PocoName}' is endpoint-only";
        else if( inner is ICommandTargetParty p && p.TargetPartyFullName != local.FullName ) refused = $"party command '{m.PocoName}' doesn't target '{local.FullName}'";
        if( refused != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Command routed from '{routed.Via[0]}' is refused: {refused}." );
            handler.SendError( monitor, token.Key, $"The routed command is refused: {refused}." );
            return (null, null);
        }
        monitor.Info( $"Executing '{m.PocoName}' routed from '{routed.Via[0]}' (via {string.Join( " > ", routed.Via )})." );
        return (inner, resultSealState);
    }

    // Seals the result of a routed command (with its validation messages, as an ICrisCallResult) for its origin.
    internal IPartySealedResult SealResult( object resultSealState, object? result, System.Collections.Immutable.ImmutableArray<UserMessage> validationMessages )
    {
        Throw.DebugAssert( _routedCommandSeal != null );
        var callResult = _callResultFactory.Create( r =>
        {
            r.Result = result;
            if( !validationMessages.IsDefaultOrEmpty ) r.ValidationMessages = [.. validationMessages];
        } );
        var w = new System.Buffers.ArrayBufferWriter<byte>();
        _pocoDirectory.WriteJson( w, callResult, withType: false, Protocol.ExchangeExportOptions );
        var sealedResult = _routedCommandSeal.SealResult( resultSealState, w.WrittenSpan );
        return _pocoDirectory.Create<IPartySealedResult>( r => r.Sealed = sealedResult );
    }

    // Reads the result of a routed command unsealed by the origin. Null when it can't be read (the reason is logged).
    internal ICrisCallResult? ReadResult( IActivityMonitor monitor, byte[] result )
    {
        try
        {
            return _callResultFactory.ReadJson( result, Protocol.ExchangeImportOptions );
        }
        catch( Exception ex )
        {
            monitor.Warn( "Unable to read the result of a routed command.", ex );
            return null;
        }
    }

    // The routed command carries the exact bytes serialized by the origin (the JSON of the command with its type, with
    // the exchange options of the channels): only the destination reads them.
    internal static byte[] Seal( PocoDirectory pocoDirectory, IAbstractCommand command )
    {
        var w = new System.Buffers.ArrayBufferWriter<byte>();
        pocoDirectory.WriteJson( w, command, withType: true, Protocol.ExchangeExportOptions );
        return w.WrittenSpan.ToArray();
    }

    static IAbstractCommand? ReadCommand( IActivityMonitor monitor, PocoDirectory pocoDirectory, byte[] sealedCommand )
    {
        try
        {
            return pocoDirectory.ReadJson( sealedCommand, Protocol.ExchangeImportOptions ) as IAbstractCommand;
        }
        catch( Exception ex )
        {
            monitor.Warn( "Unable to read the command of a routed command.", ex );
            return null;
        }
    }

    // Each hop vouches for its predecessor only: the last of Via is the sender. No loop, no nesting.
    static string? CheckChain( IRemoteParty sender, IPartyRoutedCommand routed )
    {
        var local = sender.Owner;
        if( routed.SealedCommand is not { Length: > 0 } ) return "it has no command.";
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
        // A revoked party (its name is banned until it is readmitted): a hop that still relays for it lies, or is not up
        // to date.
        if( local.GetFeature<KeyManagement.ILocalKeys>() is { } keys
            && routed.Via.FirstOrDefault( keys.IsNameBanned ) is { } banned )
        {
            return $"its Via contains '{banned}', a revoked party.";
        }
        return null;
    }

    /// <summary>
    /// Gets the next hop of a routed command on a local party (the routed command's <see cref="IPartyRoutedCommand.Via"/>
    /// doesn't contain it yet): its route of the <see cref="IPartyRoutedCommand.RouteName"/>, that must be hosted by the
    /// <see cref="IPartyRoutedCommand.Destination"/>, or the party after it in the <see cref="IPartyRoutedCommand.Path"/>.
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
        if( (routed.RouteName == null) == (routed.Path.Count == 0)
            || (routed.RouteName == null) != (routed.Destination == null) )
        {
            error = "it needs a RouteName and a Destination, or a Path.";
            return false;
        }
        if( routed.RouteName != null )
        {
            if( !local.Description.Routes.TryGetValue( routed.RouteName, out var route ) )
            {
                error = $"'{local.FullName}' has no route '{routed.RouteName}'.";
                return false;
            }
            // Any party of the System can announce a route: it is followed only to the expected party.
            if( route.Host != routed.Destination )
            {
                error = $"the route '{routed.RouteName}' of '{local.FullName}' leads to '{route.Host}' (through '{route.NextHop ?? route.Host}'), not to '{routed.Destination}'.";
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

    // Forwards the routed command and sends its answers back to the remote that sent it: the received envelope travels
    // unchanged, once the forwarded envelope filters cleared what this party can't vouch for (a user's proof it can't verify).
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
            foreach( var f in _forwardedEnvelopeFilters )
            {
                await f.FilterAsync( monitor, Party, channel.Party, routed, envelope ).ConfigureAwait( false );
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
