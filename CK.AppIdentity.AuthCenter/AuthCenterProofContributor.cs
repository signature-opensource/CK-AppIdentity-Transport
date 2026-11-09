using CK.AppIdentity.Cris;
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
///   <item>The proof of the inner command of a <see cref="IPartyRoutedCommand"/> is sent with it: each hop verifies it
///   before relaying it (see <see cref="AuthCenterProofForwardFilter"/>), the destination verifies it.</item>
/// </list>
/// </summary>
public sealed class AuthCenterProofContributor : ICrisCallEnvelopeContributor
{
    /// <inheritdoc />
    public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallEnvelope envelope )
    {
        // A routed command carries the proof of its inner command: the hops relay it unchanged.
        if( (command is IPartyRoutedCommand r ? r.Command : command) is IAuthUnsafePart
            && target.DomainName == target.Owner.DomainName
            && target.EnvironmentName == target.Owner.EnvironmentName
            && services.GetService<IAuthenticationSessionEndpoint>() is { AcceptedToken: { } token } endpoint )
        {
            var proof = (IAuthenticationCallEnvelope)envelope;
            proof.Token = token;
            proof.BindingSecretHash = endpoint.PresentedBindingSecretHash;
        }
    }
}
