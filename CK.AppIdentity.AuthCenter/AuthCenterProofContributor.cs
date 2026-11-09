using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Sends the user's proof (the token accepted by this endpoint and the binding secret hash presented with it) with the
/// commands that carry an identity, to any remote inside the System of the current local party: any party of the System
/// can relay a proof, and any party can have it verified (by its Authentication Center, see <see cref="AuthCenterProofVerifier"/>).
/// <list type="bullet">
///   <item>Only an accepted token is sent (<see cref="IAuthenticationSessionEndpoint.AcceptedToken"/>): a token that this
///   endpoint refused, or couldn't read (no Authentication Center), is never relayed.</item>
///   <item>A proof is a bearer credential: it never leaves the System.</item>
///   <item>A deferred execution has no presented proof: its commands travel without one.</item>
///   <item>The proof of the command of a <see cref="IPartyRoutedCommand"/> is sent with its seal
///   (<see cref="RoutedCommandSeal"/>): this party, the session party, signs the exact bytes of the command for its
///   destination. Each hop verifies the proof before relaying it (see <see cref="AuthCenterProofForwardFilter"/>), the
///   Authentication Center verifies the seal for the destination.</item>
/// </list>
/// </summary>
public sealed class AuthCenterProofContributor : ICrisCallEnvelopeContributor
{
    /// <inheritdoc />
    public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, IPartyRoutedCommand? routed, ICrisCallEnvelope envelope )
    {
        if( command is IAuthUnsafePart
            && target.DomainName == target.Owner.DomainName
            && target.EnvironmentName == target.Owner.EnvironmentName
            && services.GetService<IAuthenticationSessionEndpoint>() is { AcceptedToken: { } token } endpoint )
        {
            var proof = (IAuthenticationCallEnvelope)envelope;
            if( routed != null )
            {
                // Through hops, the proof is valid only with the seal of this party (the session party).
                var local = target.Owner;
                var keys = local.GetFeature<ILocalKeys>();
                var destination = routed.Path.Count > 0
                                    ? routed.Path[^1]
                                    : local.Description.Routes.TryGetValue( routed.RouteName!, out var route ) ? route.Host : null;
                if( keys == null || destination == null || routed.SealedCommand == null )
                {
                    monitor.Warn( $"'{local}' cannot seal the command routed to '{destination ?? routed.RouteName}': the user's proof is not sent." );
                    return;
                }
                (proof.RoutedSeal, proof.RoutedSignature) = RoutedCommandSeal.Create( keys, destination, token, routed.SealedCommand, DateTime.UtcNow );
            }
            proof.Token = token;
            proof.BindingSecretHash = endpoint.PresentedBindingSecretHash;
        }
    }
}
