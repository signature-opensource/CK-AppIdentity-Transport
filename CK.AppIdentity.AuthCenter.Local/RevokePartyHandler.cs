using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IRevokePartyCommand"/> on the Authentication Center: the identity of the party (given, or the one
/// it pins for its remote) is added to its System list, that it signs and adopts (it is relayed to every party of the
/// System). The command requires the Critical level; who may revoke is decided by the application (a validator).
/// </summary>
public sealed class RevokePartyHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the command.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="party">The local party.</param>
    /// <returns>The sequence number of the new list, or null when the party can't be revoked (the reason is logged).</returns>
    [CommandHandler]
    public async Task<int?> HandleAsync( IActivityMonitor monitor, IRevokePartyCommand command, CurrentLocalParty party )
    {
        var local = party.LocalParty;
        var revocations = local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterSystemList>() : null;
        if( revocations == null )
        {
            monitor.Warn( $"'{local}' is asked to revoke '{command.PartyFullName}': it is not an Authentication Center." );
            return null;
        }
        if( string.IsNullOrEmpty( command.PartyFullName ) || command.PartyFullName == local.FullName.Path )
        {
            monitor.Warn( $"'{command.PartyFullName}' can't be revoked by '{local}'." );
            return null;
        }
        var identity = command.Identity;
        if( identity == null )
        {
            var pinned = local.Remotes.FirstOrDefault( r => r.FullName.Path == command.PartyFullName )?.GetFeature<IRemoteKeys>()?.TrustedEvent;
            if( pinned == null )
            {
                monitor.Warn( $"'{command.PartyFullName}' is not a pinned remote of '{local}': the identity to revoke must be given." );
                return null;
            }
            identity = pinned.GetIdentity( command.PartyFullName ).ToArray();
        }
        if( identity.Length != KeyEvent.HashSize )
        {
            monitor.Warn( $"Invalid identity to revoke for '{command.PartyFullName}'." );
            return null;
        }
        var utcNow = DateTime.UtcNow;
        // The revoked party is no more an authorized host of any route: UpdateAsync drops the hosts of a banned name.
        var list = await revocations.UpdateAsync( monitor, ( entries, hosts ) =>
        {
            var e = entries.ToList();
            if( !e.Any( x => x.Matches( identity ) ) ) e.Add( new RevocationEntry( command.PartyFullName, identity, utcNow, nameBanned: true ) );
            return (e, hosts);
        } ).ConfigureAwait( false );

        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{command.PartyFullName}' is revoked by the AuthCenter '{local}': {list}." );
        return list?.Seq;
    }

    /// <summary>
    /// Answers the current System list of this Authentication Center (encoded), null when it has none.
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="party">The local party.</param>
    /// <returns>The encoded list or null.</returns>
    [CommandHandler]
    public byte[]? Handle( IGetSystemListQCommand command, CurrentLocalParty party )
    {
        var local = party.LocalParty;
        return local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterSystemList>()?.Current?.Encode() : null;
    }

    /// <summary>
    /// Handles the readmission of a full name: its entries no more ban the name (their identities stay revoked).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="party">The local party.</param>
    /// <returns>The sequence number of the new list, or null when the name is not banned (the reason is logged).</returns>
    [CommandHandler]
    public async Task<int?> HandleAsync( IActivityMonitor monitor, IReadmitPartyNameCommand command, CurrentLocalParty party )
    {
        var local = party.LocalParty;
        var revocations = local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterSystemList>() : null;
        var current = revocations?.Current;
        if( current == null || !current.Entries.Any( e => e.NameBanned && e.FullName == command.PartyFullName ) )
        {
            monitor.Warn( $"'{command.PartyFullName}' is not a banned name of the AuthCenter '{local}'." );
            return null;
        }
        var list = await revocations!.UpdateAsync( monitor, ( entries, hosts ) =>
        {
            var e = entries.Select( x => x.NameBanned && x.FullName == command.PartyFullName
                                            ? new RevocationEntry( x.FullName, x.Identity.Span, x.RevokedAt, nameBanned: false )
                                            : x )
                           .ToList();
            return (e, hosts);
        } ).ConfigureAwait( false );
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The name '{command.PartyFullName}' is readmitted by the AuthCenter '{local}' (its revoked identities stay refused): {list}." );
        return list?.Seq;
    }

    /// <summary>
    /// Authorizes a host for a route (see <see cref="SystemList.RouteHosts"/>): a new list is signed. The target of the
    /// route is the one the host announces when the Authentication Center sees its description (it is itself, or one of
    /// its remotes), otherwise the one of the command. The command requires the Critical level; who may send it is decided
    /// by the application (a validator).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="party">The local party.</param>
    /// <returns>The sequence number of the list, or null when it is refused (the reason is logged).</returns>
    [CommandHandler]
    public async Task<int?> HandleAsync( IActivityMonitor monitor, IAuthorizeRouteHostCommand command, CurrentLocalParty party )
    {
        var local = party.LocalParty;
        var list = local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterSystemList>() : null;
        if( list == null )
        {
            monitor.Warn( $"'{local}' is asked to authorize a host of the route '{command.RouteName}': it is not an Authentication Center." );
            return null;
        }
        if( !PartyDescription.IsValidName( command.RouteName ) || string.IsNullOrWhiteSpace( command.HostFullName ) || command.RouteName == AuthCenterFeature.RouteName )
        {
            monitor.Warn( $"Invalid route host authorization: '{command.RouteName}' hosted by '{command.HostFullName}'." );
            return null;
        }
        var target = AuthCenterSystemList.FindAnnouncedTarget( local, command.RouteName, command.HostFullName, out var seen );
        if( !seen ) target = command.Target;
        var updated = await list.UpdateAsync( monitor, ( entries, hosts ) =>
        {
            var h = hosts.Where( x => x.RouteName != command.RouteName || x.Host != command.HostFullName ).ToList();
            h.Add( new RouteHost( command.RouteName, command.HostFullName, target ) );
            return (entries, h);
        } ).ConfigureAwait( false );
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{command.HostFullName}' is authorized to host the route '{command.RouteName}' by the AuthCenter '{local}': {updated}." );
        return updated?.Seq;
    }

    /// <summary>
    /// Removes the authorization of a host for a route: a new list is signed. The command requires the Critical level.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="party">The local party.</param>
    /// <returns>The sequence number of the list, or null when it is refused (the reason is logged).</returns>
    [CommandHandler]
    public async Task<int?> HandleAsync( IActivityMonitor monitor, IRemoveRouteHostCommand command, CurrentLocalParty party )
    {
        var local = party.LocalParty;
        var list = local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterSystemList>() : null;
        if( list?.Current == null || !list.Current.RouteHosts.Any( h => h.RouteName == command.RouteName && h.Host == command.HostFullName ) )
        {
            monitor.Warn( $"'{command.HostFullName}' is not an authorized host of the route '{command.RouteName}' of the AuthCenter '{local}'." );
            return null;
        }
        var updated = await list.UpdateAsync( monitor, ( entries, hosts ) => (entries, hosts.Where( h => h.RouteName != command.RouteName || h.Host != command.HostFullName ).ToList()) )
                                .ConfigureAwait( false );
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{command.HostFullName}' is no more authorized to host the route '{command.RouteName}' by the AuthCenter '{local}': {updated}." );
        return updated?.Seq;
    }
}
