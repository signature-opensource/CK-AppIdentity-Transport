using CK.AppIdentity.KeyManagement;
using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IRevokePartyCommand"/> on the Authentication Center: the identity of the party (given, or the one
/// it pins for its remote) is added to its revocation list, that it signs and adopts (it is relayed to every party of the
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
        var revocations = local.GetFeature<LocalAuthCenter>() != null ? local.GetFeature<AuthCenterRevocations>() : null;
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
        var current = revocations.Current;
        var entries = current?.Entries.ToList() ?? [];
        if( !entries.Any( e => e.Matches( identity ) ) )
        {
            entries.Add( new RevocationEntry( command.PartyFullName, identity, utcNow, nameBanned: true ) );
        }
        var list = RevocationList.Create( local.GetRequiredFeature<ILocalKeys>(), (current?.Seq ?? 0) + 1, entries, utcNow );
        monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{command.PartyFullName}' is revoked by the AuthCenter '{local}': {list}." );
        await revocations.TryAdoptAsync( monitor, list.Encode(), null ).ConfigureAwait( false );
        return list.Seq;
    }
}
