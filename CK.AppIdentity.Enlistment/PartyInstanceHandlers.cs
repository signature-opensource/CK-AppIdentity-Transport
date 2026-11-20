using CK.AppIdentity.Cris;
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
/// Handles the dynamic instances of the Opened remote templates that the approval page shows:
/// <list type="bullet">
///   <item>
///   On the host of the approval page, the <see cref="IGetPartyInstancesQCommand"/> and the <see cref="IRemovePartyInstanceCommand"/>:
///   for each holder of the instance in the System (see <see cref="EnlistmentItems"/>), an
///   <see cref="IRemoveHeldPartyInstanceCommand"/> is sent to it (directly, or through the hub of the System), with the
///   operator's proof.
///   </item>
///   <item>
///   On the holder, the <see cref="IRemoveHeldPartyInstanceCommand"/>: Critical (the operator's proof is verified by the
///   holder through its Authentication Center), never impersonated; the instance is removed
///   (<see cref="ILocalParty.RemoveTemplateInstanceAsync"/>). Without Authentication Center, only a page on the holder
///   itself removes its instances (a routed proof can't reach the Critical level).
///   </item>
/// </list>
/// </summary>
public sealed class PartyInstanceHandlers : ISingletonAutoService
{
    readonly EnlistmentItems _items;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="items">The items of the approval page.</param>
    public PartyInstanceHandlers( EnlistmentItems items )
    {
        _items = items;
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
    /// Refuses a removal made while impersonating, on the holder.
    /// </summary>
    /// <param name="c">The message collector.</param>
    /// <param name="command">The command.</param>
    /// <param name="authentication">The authentication.</param>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IRemoveHeldPartyInstanceCommand command, AuthenticationInfo authentication )
    {
        if( authentication.IsImpersonated )
        {
            c.Error( "A party instance can't be removed while impersonating.", "AppIdentity.Enlistment.Impersonated" );
        }
    }

    /// <summary>
    /// Lists the dynamic instances of the System (see <see cref="EnlistmentItems"/>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party: the host of the approval page.</param>
    /// <param name="services">The services of the request.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The instances (one per holder of an instance).</returns>
    [CommandHandler]
    public async Task<IList<IPartyInstance>> HandleAsync( IActivityMonitor monitor,
                                                          IGetPartyInstancesQCommand command,
                                                          CurrentLocalParty current,
                                                          IServiceProvider services,
                                                          PocoDirectory pocos )
    {
        var held = await _items.GetSystemAsync( monitor, services, current.LocalParty, pocos ).ConfigureAwait( false );
        var result = held.Instances.ToList();
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
        var held = await _items.GetSystemAsync( monitor, services, host, pocos ).ConfigureAwait( false );
        foreach( var instance in held.Instances )
        {
            if( instance.PartyFullName != command.PartyFullName ) continue;
            var holder = instance.HolderFullName;
            var remove = pocos.Create<IRemoveHeldPartyInstanceCommand>( r =>
            {
                // The operator: its live proof travels with the command.
                r.ActorId = authentication.Actor.ActorId;
                r.PartyFullName = instance.PartyFullName;
            } );
            monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                          $"Actor #{authentication.Actor.ActorId} removes the instance '{instance.PartyFullName}' held by '{holder}'." );
            bool removed;
            if( holder == host.FullName.Path )
            {
                removed = await RemoveHeldAsync( monitor, host, remove ).ConfigureAwait( false );
            }
            else
            {
                var result = await _items.SendToHolderAsync( monitor, services, host, remove, holder ).ConfigureAwait( false );
                removed = result is true;
                if( result is not bool ) monitor.Warn( $"The removal of '{instance.PartyFullName}' can't reach '{holder}': {result}" );
            }
            if( removed ) ++count;
        }
        if( count == 0 ) monitor.Warn( $"No holder of the instance '{command.PartyFullName}' removed it (known by '{host.FullName}')." );
        return count;
    }

    /// <summary>
    /// Removes the instance on the party that holds it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command (Critical: the operator's proof has been verified).</param>
    /// <param name="current">The local party: the holder.</param>
    /// <returns>True if the instance has been removed.</returns>
    [CommandHandler]
    public Task<bool> HandleAsync( IActivityMonitor monitor, IRemoveHeldPartyInstanceCommand command, CurrentLocalParty current )
    {
        return RemoveHeldAsync( monitor, current.LocalParty, command );
    }

    static async Task<bool> RemoveHeldAsync( IActivityMonitor monitor, ILocalParty holder, IRemoveHeldPartyInstanceCommand command )
    {
        var remote = holder.Remotes.FirstOrDefault( r => r.FullName.Path == command.PartyFullName );
        if( remote == null || !remote.Configuration.IsDynamicInstance )
        {
            monitor.Warn( $"'{holder.FullName}' has no dynamic instance '{command.PartyFullName}'." );
            return false;
        }
        return await holder.RemoveTemplateInstanceAsync( monitor, remote ).ConfigureAwait( false );
    }
}
