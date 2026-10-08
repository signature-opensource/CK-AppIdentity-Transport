using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The "AuthCenter" feature is carried by a <see cref="ILocalParty"/> and all its <see cref="IRemoteParty"/>
/// and identifies one of the <see cref="IParty"/> as the "Authentication Center".
/// <para>
/// Note that the party that is the `AuthCenter` is also decorated by this feature and that a duplicate `AuthCenter` in
/// a <see cref="ILocalParty"/> is a configuration error.
/// </para>
/// </summary>
public interface ICrisAuthCenter
{
    /// <summary>
    /// The purpose of the tokens signed by the Authentication Center: "CK.AuthCenter.Token".
    /// </summary>
    const string TokenPurpose = "CK.AuthCenter.Token";

    /// <summary>
    /// Gets the party that is the Authentication Center.
    /// </summary>
    IParty AuthCenter { get; }

    /// <summary>
    /// Verifies a token signed by the <see cref="AuthCenter"/> (for the <see cref="TokenPurpose"/>): this is the same
    /// whether the Authentication Center is the local party or a remote (see <see cref="IPartyKeys.Verify"/>).
    /// <para>
    /// The purpose is fixed: no other signature of the Authentication Center can be taken for a token.
    /// This fails closed when the Authentication Center is not available.
    /// </para>
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="data">The signed token data.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>True if the token signature is valid now.</returns>
    bool Verify( IActivityLineEmitter logger, ReadOnlySpan<byte> data, in ApplicationSignature signature );
}
