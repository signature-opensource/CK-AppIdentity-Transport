using CK.Cris;
using CK.Core;
using CK.IO.AuthCenter;
using CK.IO.Authentication;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Handles the <see cref="IVerifyCallerProofCommand"/> of a party of the System: it relayed a user's proof and asks this
/// Authentication Center whether it is valid (<see cref="LocalAuthCenter.CheckProofAsync"/>). Any party of the System may
/// ask (the command is internal: the channel refuses it from outside the System), any party can relay a proof.
/// </summary>
public sealed class VerifyCallerProofHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the command.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="caller">The remote that sent it.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The proved identity, or null when the proof is not valid.</returns>
    [CommandHandler]
    public async Task<IAuthenticationInfoPoco?> HandleAsync( IActivityMonitor monitor, IVerifyCallerProofCommand command, IRemoteParty caller, PocoDirectory pocos )
    {
        var center = caller.Owner.GetFeature<LocalAuthCenter>();
        if( center == null )
        {
            monitor.Warn( $"'{caller}' asks '{caller.Owner}' to verify a user's proof: it is not an Authentication Center." );
            return null;
        }
        RoutedProofSeal? seal = null;
        if( command.RoutedSeal != null || command.RoutedPayloadDigest != null || command.RoutedSignature != null )
        {
            if( command.RoutedSeal == null || command.RoutedPayloadDigest == null || command.RoutedSignature == null )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' asks to verify the proof of a routed command with an incomplete seal." );
                return null;
            }
            seal = new RoutedProofSeal( command.RoutedSeal, command.RoutedPayloadDigest, command.RoutedSignature );
        }
        // The asking party is the destination of a routed command.
        var info = await center.CheckProofAsync( monitor, command.Token, command.BindingSecretHash, seal, caller.FullName.Path ).ConfigureAwait( false );
        if( info == null ) return null;
        monitor.Trace( $"A user's proof relayed by '{caller}' is verified: actor #{info.UnsafeActor.ActorId}." );
        return pocos.Create<IAuthenticationInfoPoco>( p => p.InitializeFrom( info ) );
    }
}
