using CK.AppIdentity;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.Auth;

/// <summary>
/// Optional service that verifies the user's proof received with a command (see <see cref="IAuthenticationCallEnvelope"/>):
/// only a party that can check it implements it (an authentication center: its tokens, their live session and binding).
/// Without it, a proof is ignored and the received identity is the one vouched for by the caller party, capped.
/// </summary>
public interface ICallerProofVerifier : ISingletonAutoService
{
    /// <summary>
    /// Verifies a proof.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the channel scope.</param>
    /// <param name="caller">The remote that sent the command.</param>
    /// <param name="proof">The proof.</param>
    /// <returns>The proved authentication, or null when the proof is not valid here (the reason is logged).</returns>
    ValueTask<AuthenticationInfo?> VerifyAsync( IActivityMonitor monitor, IServiceProvider services, IRemoteParty caller, IAuthenticationCallEnvelope proof );
}
