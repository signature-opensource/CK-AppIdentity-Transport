using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// A feature of a local party that checks a user's proof relayed by another party (see <see cref="AuthCenterProofVerifier"/>):
/// the <c>LocalAuthCenter</c> of the Authentication Center checks its session store, the <c>RemoteAuthCenter</c> of its
/// remotes asks it.
/// </summary>
public interface IAuthCenterProofChecker
{
    /// <summary>
    /// Checks a user's proof: its token must be valid and its session alive and still the token's (the same binding
    /// secret and the same actor). This is <see cref="CrisAuthCenter.ReadProofAsync"/> then <see cref="CheckLivenessAsync"/>,
    /// for a proof received directly.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, byte[] bindingSecretHash );

    /// <summary>
    /// Checks that the session of a proof that has been read (see <see cref="CrisAuthCenter.ReadProofAsync"/>) is alive
    /// and still the token's (the same binding secret and the same actor) and, for the proof of a routed command, its seal:
    /// the session party sealed the command for this local party (see <see cref="RoutedCommandSeal"/>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="read">The content of the token, read with its binding secret.</param>
    /// <param name="seal">The seal of the routed command that carried the proof, null for a proof received directly.</param>
    /// <returns>The proved identity, or null when the session ended or changed, or the seal is invalid (the reason is logged).</returns>
    ValueTask<AuthenticationInfo?> CheckLivenessAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal? seal );
}
