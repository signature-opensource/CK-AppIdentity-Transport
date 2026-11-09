using CK.AppIdentity;
using CK.AppIdentity.Cris;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.Auth;

/// <summary>
/// Optional service that verifies the user's proof received with a command (see <see cref="IAuthenticationCallEnvelope"/>):
/// only a party that can check it implements it (an authentication center or any of its remotes, that asks it: the tokens,
/// their live session and binding).
/// Without it, a proof is ignored and the received identity is the one vouched for by the caller party, capped.
/// </summary>
public interface ICallerProofVerifier : ISingletonAutoService
{
    /// <summary>
    /// Verifies a proof.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the channel scope.</param>
    /// <param name="sender">The remote that sent the command.</param>
    /// <param name="route">
    /// The routed command that carried the command (the <paramref name="sender"/> is then its last hop), or null when the
    /// command has been received directly.
    /// </param>
    /// <param name="proof">The proof.</param>
    /// <returns>The proved authentication, or null when the proof is not valid here (the reason is logged).</returns>
    ValueTask<AuthenticationInfo?> VerifyAsync( IActivityMonitor monitor, IServiceProvider services, IRemoteParty sender, IPartyRoutedCommand? route, IAuthenticationCallEnvelope proof );
}
