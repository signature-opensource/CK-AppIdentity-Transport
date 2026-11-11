using CK.AppIdentity.Cris;
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
/// Only the party that opened the session (<see cref="AuthCenterTokenContent.SessionParty"/>, the one that serves the
/// user's client application) may present a proof at the Critical level: the proved identity of a proof sent by another
/// party is capped at <see cref="AuthLevel.Normal"/>. A party that received the proof (a backend, a hop) can't reuse it at
/// the Critical level. A proof received directly from another party than the session party is not relayed by an honest
/// party (it has no presented token): it is a <see cref="ActivityMonitor.Tags.SecurityCritical"/> warning.
/// </para>
/// <para>
/// The proof of a routed command is valid only with its seal (<see cref="RoutedCommandSeal"/>): the session party, the
/// origin of the route, signed the exact bytes of the command for this destination. A routed proof without a valid
/// seal is ignored (a <see cref="ActivityMonitor.Tags.SecurityCritical"/> warning): the command is then executed with what
/// its caller party vouches for.
/// </para>
/// <para>
/// A local party without Authentication Center (no checker) ignores the proof: the received identity is the one vouched
/// for by the caller party, capped.
/// </para>
/// </summary>
public sealed class AuthCenterProofVerifier : ICallerProofVerifier
{
    /// <inheritdoc />
    public async ValueTask<AuthenticationInfo?> VerifyAsync( IActivityMonitor monitor, IServiceProvider services, IRemoteParty caller, IPartyRoutedCommand? route, IAuthenticationCallEnvelope proof )
    {
        var checker = caller.Owner.GetFeature<IAuthCenterProofChecker>();
        var center = caller.Owner.GetFeature<CrisAuthCenter>();
        if( checker == null || center == null || proof.Token == null )
        {
            monitor.Warn( $"'{caller.Owner}' has no Authentication Center: the user's proof sent by '{caller}' is ignored." );
            return null;
        }
        var read = await center.ReadProofAsync( monitor, proof.Token, proof.BindingSecretHash, center.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' sent a user's proof that doesn't verify: it is ignored." );
            return null;
        }
        if( route != null )
        {
            // Through hops, the proof is valid only with the seal of the session party, the origin of the route.
            var path = string.Join( " > ", route.Via );
            if( proof.RoutedSeal == null || proof.RoutedSignature == null || route.SealedCommand == null )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The user's proof of a command routed by '{path}' has no seal: it is ignored." );
                return null;
            }
            if( route.Via[0] != read.SessionParty )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The user's proof of a session opened by '{read.SessionParty}' is routed from '{path}': it is ignored." );
                return null;
            }
            var seal = new RoutedProofSeal( proof.RoutedSeal, RoutedCommandSeal.GetPayloadDigest( route.SealedCommand ), proof.RoutedSignature );
            var sealedInfo = await checker.CheckLivenessAsync( monitor, proof.Token, read, seal ).ConfigureAwait( false );
            if( sealedInfo == null )
            {
                monitor.Warn( $"The user's proof of a command routed by '{path}' is ignored (its session or its seal, see above)." );
            }
            return sealedInfo;
        }
        var info = await checker.CheckLivenessAsync( monitor, proof.Token, read, null ).ConfigureAwait( false );
        if( info != null && caller.FullName.Path != read.SessionParty )
        {
            // Only the session party may present the proof at the Critical level.
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{caller}' sent a user's proof of a session opened by '{read.SessionParty}': its level is capped at Normal." );
            info = info.WithCriticalExpires( null, center.UtcNow );
        }
        return info;
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
