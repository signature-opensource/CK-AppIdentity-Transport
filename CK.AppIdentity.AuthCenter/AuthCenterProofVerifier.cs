using CK.Auth;
using CK.Core;
using CK.IO.Authentication;
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Verifies the user's proof sent with a command by another party of the System (any party can relay it): the
/// <see cref="IAuthCenterProofChecker"/> of the receiving local party checks it, on the Authentication Center itself
/// (its session store) or on any of its remotes (they ask the Authentication Center). The proved identity keeps its level:
/// this is how a Critical command crosses a party boundary.
/// <para>
/// A party relays only a proof it verified (see <see cref="AuthCenterProofContributor"/> and
/// <see cref="AuthCenterProofForwardFilter"/>): a proof that fails the local reading (its token, its binding) is evidence
/// against the party that sent it (a <see cref="ActivityMonitor.Tags.SecurityCritical"/> warning that names it). A proof
/// whose session ended or changed is not: a logout may happen while a command travels.
/// </para>
/// <para>
/// A local party without Authentication Center (no checker) ignores the proof: the received identity is the one vouched
/// for by the caller party, capped.
/// </para>
/// </summary>
public sealed class AuthCenterProofVerifier : ICallerProofVerifier
{
    /// <inheritdoc />
    public async ValueTask<AuthenticationInfo?> VerifyAsync( IActivityMonitor monitor, IServiceProvider services, IRemoteParty caller, IAuthenticationCallEnvelope proof )
    {
        var checker = caller.Owner.GetFeature<IAuthCenterProofChecker>();
        var center = caller.Owner.GetFeature<CrisAuthCenter>();
        if( checker == null || center == null || proof.Token == null )
        {
            monitor.Warn( $"'{caller.Owner}' has no Authentication Center: the user's proof sent by '{caller}' is ignored." );
            return null;
        }
        var read = await center.ReadProofAsync( monitor, proof.Token, proof.BindingSecretHash, DateTime.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' sent a user's proof that doesn't verify: it is ignored." );
            return null;
        }
        return await checker.CheckLivenessAsync( monitor, proof.Token, read ).ConfigureAwait( false );
    }

    /// <summary>
    /// Gets the identity stated by the Authentication Center in its answer to the verification of a proof (see
    /// <c>IVerifyCallerProofCommand</c>): the one case where an <see cref="IAuthenticationInfoPoco"/> becomes a trusted
    /// authentication, because it is the Authentication Center's statement, received from it.
    /// </summary>
    /// <param name="info">The answer of the Authentication Center.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The proved identity.</returns>
    public static AuthenticationInfo FromAuthCenterAnswer( IAuthenticationInfoPoco info, DateTime utcNow )
    {
        Throw.CheckNotNullArgument( info );
        return AuthenticationInfo.Create( ToActor( info.UnsafeActualActor ),
                                          ToActor( info.UnsafeActor ),
                                          info.Expires,
                                          info.CriticalExpires,
                                          info.DeviceId,
                                          utcNow );

        static ActorInfo ToActor( IActorInfoPoco a ) => new ActorInfo( a.ActorId,
                                                                       a.ActorName,
                                                                       a.Level,
                                                                       a.Schemes.Select( s => new SchemeInfo( s.Scheme, s.LastUsed ) ).ToImmutableArray() );
    }
}
