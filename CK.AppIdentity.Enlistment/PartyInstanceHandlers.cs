using CK.AppIdentity.Cris;
using CK.AppIdentity.TransportLayer;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Enlistment;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Enlistment;

/// <summary>
/// Handles the dynamic instances of the Opened remote templates that reach the approval page:
/// <list type="bullet">
///   <item>
///   On the host of the approval page, the <see cref="IGetPartyInstancesQCommand"/> and the <see cref="IRemovePartyInstanceCommand"/>:
///   for each holder of the instance collected along the "Enlistment" route, an <see cref="IRemoveHeldPartyInstanceCommand"/>
///   is sent down to it by the reversed path of the item.
///   </item>
///   <item>
///   On the holder, the <see cref="IRemoveHeldPartyInstanceCommand"/>: accepted only from the host of its "Enlistment" route,
///   the instance is removed (<see cref="ILocalParty.RemoveTemplateInstanceAsync"/>).
///   </item>
/// </list>
/// </summary>
public sealed class PartyInstanceHandlers : ISingletonAutoService
{
    readonly PartyRoutedCommandSender _sender;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="sender">The sender of the routed commands.</param>
    public PartyInstanceHandlers( PartyRoutedCommandSender sender )
    {
        _sender = sender;
    }

    /// <summary>
    /// Refuses a removal made while impersonating: the operator removes as itself.
    /// </summary>
    /// <param name="c">The message collector.</param>
    /// <param name="command">The command.</param>
    /// <param name="authentication">The authentication.</param>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IRemovePartyInstanceCommand command, AuthenticationInfo authentication )
    {
        if( authentication.IsImpersonated )
        {
            c.Error( "A party instance can't be removed while impersonating.", "AppIdentity.Enlistment.Impersonated" );
        }
    }

    /// <summary>
    /// Lists the dynamic instances collected along the "Enlistment" route by the local party (the host of the approval page).
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party: the host of the approval page.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The instances (one per holder of an instance).</returns>
    [CommandHandler]
    public IList<IPartyInstance> Handle( IGetPartyInstancesQCommand command, CurrentLocalParty current, PocoDirectory pocos )
    {
        var result = new List<IPartyInstance>();
        if( current.LocalParty.Description.Collected.TryGetValue( TransportFeatureDriver.EnlistmentRouteName, out var items ) )
        {
            foreach( var item in items )
            {
                if( !TransportFeatureDriver.TryReadPartyInstanceValue( item.Value, out var instance ) ) continue;
                result.Add( pocos.Create<IPartyInstance>( i =>
                {
                    i.PartyFullName = instance.PartyFullName;
                    i.HolderFullName = item.Holder;
                    i.TemplatePartyName = instance.TemplatePartyName;
                } ) );
            }
        }
        result.Sort( ( a, b ) => StringComparer.Ordinal.Compare( a.PartyFullName, b.PartyFullName ) );
        return result;
    }

    /// <summary>
    /// Sends the removal of an instance to every party that holds it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party: the host of the approval page.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="services">The services of the scope.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The number of holders that removed the instance.</returns>
    [CommandHandler]
    public async Task<int> HandleAsync( IActivityMonitor monitor,
                                        IRemovePartyInstanceCommand command,
                                        CurrentLocalParty current,
                                        AuthenticationInfo authentication,
                                        IServiceProvider services,
                                        PocoDirectory pocos )
    {
        var host = current.LocalParty;
        int count = 0;
        if( host.Description.Collected.TryGetValue( TransportFeatureDriver.EnlistmentRouteName, out var items ) )
        {
            foreach( var item in items )
            {
                if( !TransportFeatureDriver.TryReadPartyInstanceValue( item.Value, out var instance )
                    || instance.PartyFullName != command.PartyFullName )
                {
                    continue;
                }
                var remove = pocos.Create<IRemoveHeldPartyInstanceCommand>( r => r.PartyFullName = instance.PartyFullName );
                monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                              $"Actor #{authentication.Actor.ActorId} removes the instance '{instance.PartyFullName}' held by '{item.Holder}'." );
                bool removed;
                if( item.Length == 1 )
                {
                    removed = await RemoveHeldAsync( monitor, host, host.FullName, remove ).ConfigureAwait( false );
                }
                else
                {
                    var result = await _sender.SendAlongPathAsync( monitor, services, host, remove, item.Path.Reverse() ).ConfigureAwait( false );
                    removed = result is true;
                    if( result is not bool ) monitor.Warn( $"The removal of '{instance.PartyFullName}' can't reach '{item.Holder}': {result}" );
                }
                if( removed ) ++count;
            }
        }
        if( count == 0 ) monitor.Warn( $"No holder of the instance '{command.PartyFullName}' removed it (known by '{host.FullName}')." );
        return count;
    }

    /// <summary>
    /// Removes the instance on the party that holds it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party: the holder.</param>
    /// <param name="authentication">The authentication: its caller party must be the host of the "Enlistment" route.</param>
    /// <returns>True if the instance has been removed.</returns>
    [CommandHandler]
    public Task<bool> HandleAsync( IActivityMonitor monitor,
                                   IRemoveHeldPartyInstanceCommand command,
                                   CurrentLocalParty current,
                                   AuthenticationInfo authentication )
    {
        return RemoveHeldAsync( monitor, current.LocalParty, authentication.CallerPartyFullName, command );
    }

    static async Task<bool> RemoveHeldAsync( IActivityMonitor monitor, ILocalParty holder, string? caller, IRemoveHeldPartyInstanceCommand command )
    {
        // Fail closed: only from a host of the route (an approval page of the System).
        if( caller == null || holder.Description.FindRoute( TransportFeatureDriver.EnlistmentRouteName, caller ) == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"'{holder.FullName}' refuses the removal of '{command.PartyFullName}' from '{caller}': it is not a host of its \"Enlistment\" route." );
            return false;
        }
        var remote = holder.Remotes.FirstOrDefault( r => r.FullName.Path == command.PartyFullName );
        if( remote == null || !remote.Configuration.IsDynamicInstance )
        {
            monitor.Warn( $"'{holder.FullName}' has no dynamic instance '{command.PartyFullName}'." );
            return false;
        }
        return await holder.RemoveTemplateInstanceAsync( monitor, remote ).ConfigureAwait( false );
    }
}
