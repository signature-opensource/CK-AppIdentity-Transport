using CK.AppIdentity.Cris;
using CK.Auth;
using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// Sends the user's proof (the token and the binding secret hash presented to this endpoint) with the commands that carry
/// an identity, to any remote inside the System of the current local party: any party of the System can relay a proof,
/// and any party can have it verified (by its Authentication Center, see <see cref="AuthCenterProofVerifier"/>). A proof is
/// a bearer credential: it never leaves the System. A deferred execution has no presented proof: its commands travel
/// without one.
/// </summary>
public sealed class AuthCenterProofContributor : ICrisCallEnvelopeContributor
{
    /// <inheritdoc />
    public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallEnvelope envelope )
    {
        if( command is IAuthUnsafePart
            && target.DomainName == target.Owner.DomainName
            && target.EnvironmentName == target.Owner.EnvironmentName
            && services.GetService<IAuthenticationSessionEndpoint>() is { PresentedToken: { } token } endpoint )
        {
            var proof = (IAuthenticationCallEnvelope)envelope;
            proof.Token = token;
            proof.BindingSecretHash = endpoint.PresentedBindingSecretHash;
        }
    }
}
