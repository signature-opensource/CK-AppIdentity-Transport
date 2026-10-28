using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Executes the commands that have no local handler on the remote parties, over their <see cref="CrisChannelFeature"/>,
/// and routes the party commands (<see cref="ICommandTargetParty"/>) by their target.
/// <list type="bullet">
///   <item>
///   A singleton command (the default) is sent to <b>the</b> remote of the current local party that accepts it (see
///   <see cref="CrisChannelFeature.AcceptedCommands"/>). None is "no route"; more than one is a deployment error.
///   </item>
///   <item>
///   A party command executes where its target is: the current local party (here), another local party of this application
///   (here, inline, with this party as the <see cref="CurrentLocalParty"/>), or a remote of the current local party (sent
///   to it if it accepts the command). Anything else is "no route".
///   </item>
/// </list>
/// While a remote of the current local party has not advertised its accepted commands yet (it is not connected yet), a
/// command without route waits for it, up to the <see cref="Timeout"/>. This fails closed: no route, an unavailable
/// remote or no answer within the <see cref="Timeout"/> are error results, never a local execution.
/// <para>
/// The caller-only events of a remote execution travel with its response: they are emitted in the caller's execution
/// context. Its routed events are dispatched where it executed.
/// </para>
/// </summary>
public sealed class ChannelCrisRemoteDispatcher : ICrisRemoteDispatcher
{
    readonly ApplicationIdentityService _identity;
    readonly IEnumerable<ICrisCallContextContributor> _contributors;

    /// <summary>
    /// The maximal time to wait for a route or for the answer of a remote: 30 seconds.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds( 30 );

    /// <summary>
    /// Initializes a new dispatcher.
    /// </summary>
    /// <param name="identity">The application identity service.</param>
    /// <param name="contributors">The contributors to the call context of the dispatched commands.</param>
    public ChannelCrisRemoteDispatcher( ApplicationIdentityService identity, IEnumerable<ICrisCallContextContributor> contributors )
    {
        _identity = identity;
        _contributors = contributors;
    }

    /// <inheritdoc />
    public async Task<RawCrisExecutor.RawResult> DispatchAsync( IServiceProvider services, IAbstractCommand command )
    {
        var local = GetCurrentLocalParty( services );
        var name = command.CrisPocoModel.PocoName;
        var routes = GetRoutes( local, name );
        if( routes.Count == 0 && await WaitForAdvertisementsAsync( local ).ConfigureAwait( false ) )
        {
            routes = GetRoutes( local, name );
        }
        if( routes.Count == 0 )
        {
            return Error( services, $"Command '{name}' has no local handler and no remote of '{local.FullName}' accepts it.", "Cris.NoRoute" );
        }
        if( routes.Count > 1 )
        {
            return Error( services, $"Deployment error: command '{name}' is handled by {routes.Count} remotes of '{local.FullName}' ({routes.Select( c => c.Party.FullName.Path ).Concatenate()}).", "Cris.MultipleRoutes" );
        }
        return await SendAsync( services, routes[0], command ).ConfigureAwait( false );
    }

    /// <inheritdoc />
    public Task<RawCrisExecutor.RawResult>? RoutePartyCommand( IServiceProvider services, IAbstractCommand command )
    {
        var target = ((ICommandTargetParty)command).TargetPartyFullName;
        if( string.IsNullOrWhiteSpace( target ) )
        {
            return Task.FromResult( Error( services, $"The target party of '{command.CrisPocoModel.PocoName}' is required.", "Cris.MissingTargetParty" ) );
        }
        var local = GetCurrentLocalParty( services );
        if( local.FullName == target ) return null;
        ILocalParty? otherLocal = _identity.FullName == target
                                    ? _identity
                                    : _identity.TenantDomains.FirstOrDefault( t => t.FullName == target );
        if( otherLocal != null ) return SwitchTenantAsync( services, otherLocal, command );
        var remote = local.Remotes.FirstOrDefault( r => r.FullName == target );
        if( remote != null && command.CrisPocoModel.Exposure != CrisExposure.Private )
        {
            var channel = remote.GetFeature<CrisChannelFeature>();
            if( channel != null ) return SendToTargetAsync( services, channel, command );
        }
        return Task.FromResult( Error( services, $"Party command '{command.CrisPocoModel.PocoName}' has no route from '{local.FullName}' to '{target}'.", "Cris.NoRoute" ) );
    }

    // Another local party of this application: executed here, inline, with that party as the CurrentLocalParty.
    static Task<RawCrisExecutor.RawResult> SwitchTenantAsync( IServiceProvider services, ILocalParty target, IAbstractCommand command )
    {
        if( services.GetService<ICrisCommandContext>() is not CrisExecutionContext context )
        {
            return Task.FromResult( Error( services, $"Party command '{command.CrisPocoModel.PocoName}' for '{target.FullName}' requires an execution context to switch to this local party.", "Cris.NoRoute" ) );
        }
        var hub = services.GetRequiredService<AmbientServiceHub>().CleanClone();
        hub.Override( new CurrentLocalParty( target ) );
        return context.RawExecuteInlineAsync( hub, command );
    }

    async Task<RawCrisExecutor.RawResult> SendToTargetAsync( IServiceProvider services, CrisChannelFeature channel, IAbstractCommand command )
    {
        if( !await channel.WaitForAcceptedCommandsAsync( Timeout ).ConfigureAwait( false ) )
        {
            return Error( services, $"Party '{channel.Party.FullName}' is not available.", "Cris.Unavailable" );
        }
        if( channel.AcceptedCommands?.Contains( command.CrisPocoModel.PocoName ) is not true )
        {
            return Error( services, $"Party command '{command.CrisPocoModel.PocoName}' is not accepted by '{channel.Party.FullName}'.", "Cris.NotAccepted" );
        }
        return await SendAsync( services, channel, command ).ConfigureAwait( false );
    }

    static List<CrisChannelFeature> GetRoutes( ILocalParty local, string name )
    {
        var routes = new List<CrisChannelFeature>();
        foreach( var r in local.Remotes )
        {
            if( r.GetFeature<CrisChannelFeature>() is { } c && c.AcceptedCommands?.Contains( name ) is true ) routes.Add( c );
        }
        return routes;
    }

    // True if at least one remote had not advertised yet (we waited for them).
    static async Task<bool> WaitForAdvertisementsAsync( ILocalParty local )
    {
        var pending = local.Remotes.Select( r => r.GetFeature<CrisChannelFeature>() )
                                   .Where( c => c != null && c.AcceptedCommands == null )
                                   .Select( c => c!.WaitForAcceptedCommandsAsync( Timeout ) )
                                   .ToList();
        if( pending.Count == 0 ) return false;
        await Task.WhenAll( pending ).ConfigureAwait( false );
        return true;
    }

    async Task<RawCrisExecutor.RawResult> SendAsync( IServiceProvider services, CrisChannelFeature channel, IAbstractCommand command )
    {
        var monitor = services.GetRequiredService<IActivityMonitor>();
        var context = services.GetService<ICrisCommandContext>();
        var executing = channel.SendCommand( monitor, command, callContext: CreateCallContext( monitor, services, channel.Party, command ) );
        // The caller-only immediate events of the remote execution are the ones of the caller.
        if( context != null )
        {
            executing.ImmediateEvents.Added.Async += ( m, e, cancel ) => context.EmitEventAsync( e );
        }
        IExecutedCommand executed;
        try
        {
            executed = await executing.ExecutedCommand.WaitAsync( Timeout ).ConfigureAwait( false );
        }
        catch( TimeoutException )
        {
            return Error( services, $"Party '{channel.Party.FullName}' did not answer '{command.CrisPocoModel.PocoName}' within {Timeout}.", "Cris.Timeout" );
        }
        // Its final caller-only events too.
        if( context != null )
        {
            foreach( var e in executed.Events ) await context.EmitEventAsync( e ).ConfigureAwait( false );
        }
        UserMessageCollector? messages = null;
        if( executed.ValidationMessages.Length > 0 )
        {
            messages = new UserMessageCollector( services.GetRequiredService<CurrentCultureInfo>() );
            foreach( var m in executed.ValidationMessages ) messages.UserMessages.Add( m );
        }
        return new RawCrisExecutor.RawResult( executed.Result, messages );
    }

    ICrisCallContext? CreateCallContext( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command )
    {
        ICrisCallContext? context = null;
        bool hasData = false;
        foreach( var c in _contributors )
        {
            context ??= services.GetRequiredService<PocoDirectory>().Create<ICrisCallContext>();
            hasData |= c.Contribute( monitor, services, target, command, context );
        }
        return hasData ? context : null;
    }

    static ILocalParty GetCurrentLocalParty( IServiceProvider services )
    {
        return services.GetRequiredService<CurrentLocalParty>().LocalParty;
    }

    static RawCrisExecutor.RawResult Error( IServiceProvider services, string text, string resName )
    {
        var monitor = services.GetService<IActivityMonitor>();
        monitor?.Error( text );
        var e = services.GetRequiredService<PocoDirectory>().Create<ICrisResultError>();
        e.Errors.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) );
        return new RawCrisExecutor.RawResult( e, null );
    }
}
