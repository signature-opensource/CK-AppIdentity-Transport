using CK.Core;
using CK.Cris;
using CK.IO.AuthCenter;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Handles the <see cref="IGetPartyActorIdsQCommand"/> of a remote: the PartyActor identifiers of the caller and of
/// this Authentication Center, as set by the PartyActor registrar (CK.DB.AppIdentity). Only a remote of the
/// Authentication Center that has its "AuthCenter" feature receives them; 0 when they are not resolved here.
/// </summary>
public sealed class AuthCenterPartyActorIdsHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the query.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The identifiers.</returns>
    [CommandHandler]
    public IPartyActorIds Handle( IActivityMonitor monitor, IGetPartyActorIdsQCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var local = AuthCenterEncryptionKeyHandler.GetLocal( caller );
        if( local == null )
        {
            Throw.InvalidOperationException( $"'{caller}' is not a remote of an AuthCenter here." );
        }
        if( caller.PartyActorId == 0 || local.Party.PartyActorId == 0 )
        {
            monitor.Warn( $"The PartyActor identifiers of '{caller}' or '{local.Party}' are not resolved: is CK.DB.AppIdentity installed?" );
        }
        return pocos.Create<IPartyActorIds>( ids =>
        {
            ids.CallerPartyActorId = caller.PartyActorId;
            ids.AuthCenterPartyActorId = local.Party.PartyActorId;
        } );
    }
}
