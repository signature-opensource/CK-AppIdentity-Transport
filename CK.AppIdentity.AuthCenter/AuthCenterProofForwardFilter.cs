using CK.AppIdentity.Cris;
using CK.Auth;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Verifies the user's proof of a routed command before this party forwards it to its next hop: a party never relays a
/// proof it didn't verify (see <see cref="AuthCenterProofContributor"/> for the party that sends it first).
/// <list type="bullet">
///   <item>With an Authentication Center (local or remote), the proof is read here (<see cref="CrisAuthCenter.ReadProofAsync"/>:
///   its token and its binding, no round trip: the liveness is checked by the destination). A proof that doesn't verify is
///   evidence against the sender (a <see cref="ActivityMonitor.Tags.SecurityCritical"/> warning that names it) and is
///   removed.</item>
///   <item>Without Authentication Center, the proof can't be verified here: it is removed (the routed command arrives
///   without it, at the level its caller party may vouch for).</item>
/// </list>
/// </summary>
public sealed class AuthCenterProofForwardFilter : ICrisForwardedEnvelopeFilter
{
    /// <inheritdoc />
    public async ValueTask FilterAsync( IActivityMonitor monitor, IRemoteParty sender, IRemoteParty target, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        if( envelope is not IAuthenticationCallEnvelope { Token: { } token } proof ) return;
        var center = sender.Owner.GetFeature<CrisAuthCenter>();
        if( center == null )
        {
            monitor.Info( $"'{sender.Owner}' has no Authentication Center: the user's proof sent by '{sender}' is not relayed to '{target}'." );
            Clear( proof );
            return;
        }
        if( await center.ReadProofAsync( monitor, token, proof.BindingSecretHash, center.UtcNow ).ConfigureAwait( false ) == null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{sender}' sent a user's proof that doesn't verify: it is not relayed to '{target}'." );
            Clear( proof );
        }

        static void Clear( IAuthenticationCallEnvelope proof )
        {
            proof.Token = null;
            proof.BindingSecretHash = null;
            proof.RoutedSeal = null;
            proof.RoutedSignature = null;
        }
    }
}
