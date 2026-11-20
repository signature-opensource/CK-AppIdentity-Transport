using CK.AppIdentity.Cris;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Enlistment;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Enlistment;

/// <summary>
/// Asks a party what it holds for the approval page: its pending approvals and the approved dynamic instances of its Opened
/// remote templates. With <see cref="IncludeRemotes"/>, the party (the hub of the System, its Authentication Center) answers what
/// its connected remotes hold as well. Internal to the System.
/// </summary>
[Internal]
public interface IGetHeldEnlistmentQCommand : ICommand<IHeldEnlistment>
{
    /// <summary>
    /// Gets or sets whether the receiver also asks its connected remotes (the hub of the System answers for the System).
    /// </summary>
    bool IncludeRemotes { get; set; }
}

/// <summary>
/// What parties hold for the approval page (see <see cref="IGetHeldEnlistmentQCommand"/>).
/// </summary>
public interface IHeldEnlistment : IPoco
{
    /// <summary>
    /// Gets the pending approvals.
    /// </summary>
    IList<IPendingApproval> Approvals { get; }

    /// <summary>
    /// Gets the approved dynamic instances of the Opened remote templates.
    /// </summary>
    IList<IPartyInstance> Instances { get; }
}

/// <summary>
/// What the approval page shows and acts on: the items held by the parties of the System. They are asked, never announced:
/// a System is a star around its Authentication Center, the hub of its administration (see <see cref="IPartyRelay"/>).
/// <list type="bullet">
///   <item>The host of the page asks its hub (<see cref="IGetHeldEnlistmentQCommand.IncludeRemotes"/>): the hub answers its own items
///   and the ones of its connected remotes.</item>
///   <item>Without hub (the page is on the Authentication Center, or there is no Authentication Center), the host asks its
///   own connected remotes.</item>
/// </list>
/// </summary>
public sealed class EnlistmentItems : ISingletonAutoService
{
    readonly PartyRoutedCommandSender _sender;
    readonly IPartyRelay? _relay;

    /// <summary>
    /// Initializes the service.
    /// </summary>
    /// <param name="sender">The sender of the routed commands.</param>
    /// <param name="relay">The optional hub of the System.</param>
    public EnlistmentItems( PartyRoutedCommandSender sender, IPartyRelay? relay = null )
    {
        _sender = sender;
        _relay = relay;
    }

    /// <summary>
    /// Gets the items held by a local party.
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The items.</returns>
    public IHeldEnlistment GetHeld( ILocalParty local, PocoDirectory pocos )
    {
        Throw.CheckNotNullArgument( local );
        var held = pocos.Create<IHeldEnlistment>();
        foreach( var p in TransportFeatureDriver.GetHeldPendingApprovals( local ) )
        {
            held.Approvals.Add( pocos.Create<IPendingApproval>( a =>
            {
                a.PartyFullName = p.PartyFullName;
                a.HolderFullName = p.HolderFullName;
                a.KeyFingerprint = p.Fingerprint;
                a.Kind = p.Kind;
                a.Since = p.Since;
                a.TemplatePartyName = p.TemplatePartyName;
                a.CompetingKeyCount = p.CompetingKeyCount;
            } ) );
        }
        foreach( var i in TransportFeatureDriver.GetHeldPartyInstances( local ) )
        {
            held.Instances.Add( pocos.Create<IPartyInstance>( x =>
            {
                x.PartyFullName = i.PartyFullName;
                x.HolderFullName = i.HolderFullName;
                x.TemplatePartyName = i.TemplatePartyName;
            } ) );
        }
        return held;
    }

    /// <summary>
    /// Gets the items held in the System, as a local party sees them: its own ones and the ones of its hub (that answers for
    /// the System), or, without hub, the ones of its connected remotes. A party that can't be asked is skipped (logged).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the request.</param>
    /// <param name="local">The local party (the host of the approval page).</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The items, without duplicates (one per party and holder).</returns>
    public async Task<IHeldEnlistment> GetSystemAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, PocoDirectory pocos )
    {
        var result = GetHeld( local, pocos );
        var hub = _relay?.GetHub( local );
        if( hub != null )
        {
            Merge( result, await AskAsync( monitor, services, local, hub, true, pocos ).ConfigureAwait( false ) );
        }
        else
        {
            foreach( var r in GetAskedRemotes( local ) )
            {
                Merge( result, await AskAsync( monitor, services, local, r, false, pocos ).ConfigureAwait( false ) );
            }
        }
        return result;
    }

    // The connected remotes of the System of the local party that answer the query.
    static IEnumerable<IRemoteParty> GetAskedRemotes( ILocalParty local )
    {
        var name = typeof( IGetHeldEnlistmentQCommand ).FullName;
        return local.Remotes.Where( r => !r.IsDestroyed
                                         && r.DomainName == local.DomainName
                                         && r.EnvironmentName == local.EnvironmentName
                                         && r.GetFeature<CrisChannelFeature>()?.AcceptedCommands?.Contains( name! ) is true )
                            .ToList();
    }

    async Task<IHeldEnlistment?> AskAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, IRemoteParty remote, bool includeRemotes, PocoDirectory pocos )
    {
        var query = pocos.Create<IGetHeldEnlistmentQCommand>( q => q.IncludeRemotes = includeRemotes );
        var result = await _sender.SendAlongPathAsync( monitor, services, local, query, [local.FullName.Path, remote.FullName.Path] ).ConfigureAwait( false );
        if( result is IHeldEnlistment held ) return held;
        monitor.Warn( $"'{remote}' can't be asked what it holds for the approval page: {result}" );
        return null;
    }

    static void Merge( IHeldEnlistment target, IHeldEnlistment? other )
    {
        if( other == null ) return;
        foreach( var a in other.Approvals )
        {
            if( !target.Approvals.Any( x => x.PartyFullName == a.PartyFullName && x.HolderFullName == a.HolderFullName ) ) target.Approvals.Add( a );
        }
        foreach( var i in other.Instances )
        {
            if( !target.Instances.Any( x => x.PartyFullName == i.PartyFullName && x.HolderFullName == i.HolderFullName ) ) target.Instances.Add( i );
        }
    }

    /// <summary>
    /// Sends a command to a holder: a local call is the caller's job (null is returned when the holder is the local party).
    /// The holder is a remote of the local party, or reached through its hub.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the request (the operator's proof travels with the command).</param>
    /// <param name="local">The local party (the host of the approval page).</param>
    /// <param name="command">The command.</param>
    /// <param name="holder">The full name of the holder.</param>
    /// <returns>The result, or an error.</returns>
    public Task<object?> SendToHolderAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, IAbstractCommand command, string holder )
    {
        return _sender.SendToAsync( monitor, services, local, command, holder );
    }

    /// <summary>
    /// Answers what the local party holds (and, with <see cref="IGetHeldEnlistmentQCommand.IncludeRemotes"/>, what its connected
    /// remotes hold).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party.</param>
    /// <param name="services">The services of the request.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The items.</returns>
    [CommandHandler]
    public async Task<IHeldEnlistment> HandleAsync( IActivityMonitor monitor,
                                                    IGetHeldEnlistmentQCommand command,
                                                    CurrentLocalParty current,
                                                    IServiceProvider services,
                                                    PocoDirectory pocos )
    {
        var local = current.LocalParty;
        var result = GetHeld( local, pocos );
        if( command.IncludeRemotes )
        {
            foreach( var r in GetAskedRemotes( local ) )
            {
                Merge( result, await AskAsync( monitor, services, local, r, false, pocos ).ConfigureAwait( false ) );
            }
        }
        return result;
    }
}
