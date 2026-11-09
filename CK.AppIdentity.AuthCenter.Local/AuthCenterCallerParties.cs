using CK.Auth;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The policy of an Authentication Center for its caller parties (see CK.AppIdentity.Cris.Authentication): its remotes
/// that have its "AuthCenter" feature may act for any user up to <see cref="AuthLevel.Normal"/>; any other caller is
/// refused. (A caller party alone never reaches Critical: that requires the user's proof, see <see cref="AuthCenterProofVerifier"/>.)
/// </summary>
public sealed class AuthCenterCallerPartyService : ICallerPartyService
{
    readonly ApplicationIdentityService _identity;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterCallerPartyService"/>.
    /// </summary>
    /// <param name="identity">The application identity service.</param>
    public AuthCenterCallerPartyService( ApplicationIdentityService identity )
    {
        _identity = identity;
    }

    /// <inheritdoc />
    public ValueTask<AuthLevel> GetMaxLevelAsync( IActivityMonitor monitor, string callerPartyFullName, ActorInfo actualActor, ActorInfo actor )
    {
        foreach( var remote in _identity.AllRemotes )
        {
            if( remote.FullName.Path == callerPartyFullName && LocalAuthCenter.GetLocal( remote ) != null )
            {
                return ValueTask.FromResult( AuthLevel.Normal );
            }
        }
        return ValueTask.FromResult( AuthLevel.None );
    }
}
