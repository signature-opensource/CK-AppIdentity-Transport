using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The seal of the routed commands that carry a user's proof (see <see cref="RoutedCommandSeal"/>): at the origin, the
/// session party signs the exact bytes of the command for its destination; the Authentication Center verifies the seal
/// (see <see cref="AuthCenterProofVerifier"/>). A routed command without a proof is not sealed.
/// <para>
/// When the origin can't seal (no key management), the proof is not sent: the command travels without it.
/// </para>
/// </summary>
public sealed class AuthCenterRoutedCommandSeal : ICrisRoutedCommandSeal
{
    /// <inheritdoc />
    public ValueTask<bool> SealAsync( IActivityMonitor monitor,
                                      IServiceProvider services,
                                      ILocalParty origin,
                                      string destination,
                                      IAbstractCommand command,
                                      IPartyRoutedCommand routed,
                                      ICrisCallEnvelope envelope )
    {
        if( envelope is IAuthenticationCallEnvelope { Token: { } token } proof && routed.SealedCommand != null )
        {
            var keys = origin.GetFeature<ILocalKeys>();
            if( keys == null )
            {
                monitor.Warn( $"'{origin}' cannot seal the command routed to '{destination}': the user's proof is not sent." );
                proof.Token = null;
                proof.BindingSecretHash = null;
            }
            else
            {
                (proof.RoutedSeal, proof.RoutedSignature) = RoutedCommandSeal.Create( keys, destination, token, routed.SealedCommand, DateTime.UtcNow );
            }
        }
        return ValueTask.FromResult( true );
    }

    /// <inheritdoc />
    public ValueTask<byte[]?> UnsealAsync( IActivityMonitor monitor, IRemoteParty sender, IPartyRoutedCommand routed, ICrisCallEnvelope envelope )
    {
        // Signed, in clear: the seal is verified with the proof (see AuthCenterProofVerifier).
        return ValueTask.FromResult( routed.SealedCommand );
    }
}
