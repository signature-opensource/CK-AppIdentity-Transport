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
    /// secret and the same actor).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, string bindingSecretHash );
}
