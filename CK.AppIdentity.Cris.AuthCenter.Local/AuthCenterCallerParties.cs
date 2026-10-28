using CK.Auth;
using CK.Core;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

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
    public ValueTask<AuthLevel> GetMaxLevelAsync( IActivityMonitor monitor, int callerPartyId, ActorInfo actualActor, ActorInfo actor )
    {
        foreach( var remote in _identity.AllRemotes )
        {
            if( remote.PartyActorId == callerPartyId && AuthCenterEncryptionKeyHandler.GetLocal( remote ) != null )
            {
                return ValueTask.FromResult( AuthLevel.Normal );
            }
        }
        return ValueTask.FromResult( AuthLevel.None );
    }
}

/// <summary>
/// Verifies the user's proof sent by a remote of the Authentication Center with a command: a token of this Authentication
/// Center, presented with the binding secret of its session, whose session is alive and is still the token's one (same
/// binding and same actor: a refresh rotates the binding, a logout or a revocation deletes the session, an impersonation
/// changes the actor). The proved identity keeps its level: this is how a Critical command crosses a party boundary.
/// </summary>
public sealed class AuthCenterProofVerifier : ICallerProofVerifier
{
    /// <inheritdoc />
    public async ValueTask<AuthenticationInfo?> VerifyAsync( IActivityMonitor monitor, IServiceProvider services, IRemoteParty caller, IAuthenticationCallEnvelope proof )
    {
        var center = AuthCenterEncryptionKeyHandler.GetLocal( caller );
        if( center == null || proof.Token == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' is not a remote of an AuthCenter here: its user's proof is ignored." );
            return null;
        }
        var utcNow = DateTime.UtcNow;
        var read = await center.Center.ReadTokenAsync( monitor, proof.Token, utcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( $"'{caller}' sent an invalid user's token: it is ignored." );
            return null;
        }
        if( proof.BindingSecretHash == null || !FixedTimeEquals( proof.BindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' sent a user's token without the binding secret of its session: it is ignored." );
            return null;
        }
        var session = await center.Sessions.TryReadAsync( monitor, read.Info.UnsafeActualActor.ActorId, read.SessionId ).ConfigureAwait( false );
        if( session == null
            || session.Expires <= utcNow
            || session.ActorId != read.Info.UnsafeActor.ActorId
            || !FixedTimeEquals( session.BindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( $"'{caller}' sent the token of a session that ended or changed: it is ignored." );
            return null;
        }
        return read.Info;
    }

    static bool FixedTimeEquals( string a, string b ) => CryptographicOperations.FixedTimeEquals( Encoding.ASCII.GetBytes( a ), Encoding.ASCII.GetBytes( b ) );
}
