using CK.AppIdentity.Cris;
using CK.Auth;
using CK.Core;
using CK.Cris;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Sends the user's proof (the token and the binding secret hash presented to this endpoint) with the commands that carry
/// an identity, <b>only</b> to the Authentication Center of the current local party: a proof is a bearer credential, any
/// other party could replay it. A deferred execution has no presented proof: its commands travel without one.
/// </summary>
public sealed class AuthCenterProofContributor : ICrisCallEnvelopeContributor
{
    /// <inheritdoc />
    public void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallEnvelope envelope )
    {
        if( command is IAuthUnsafePart
            && services.GetService<CurrentLocalParty>()?.LocalParty.GetFeature<RemoteAuthCenter>()?.Center.AuthCenter == target
            && services.GetService<IAuthenticationSessionEndpoint>() is { PresentedToken: { } token } endpoint )
        {
            var proof = (IAuthenticationCallEnvelope)envelope;
            proof.Token = token;
            proof.BindingSecretHash = endpoint.PresentedBindingSecretHash;
        }
    }
}
