using CK.Cris;
using CK.IO.Authentication;

namespace CK.IO.AuthCenter;

/// <summary>
/// Asks the Authentication Center to verify a user's proof relayed by another party (see the <c>IAuthenticationCallEnvelope</c>
/// of CK.AppIdentity.Cris.Authentication): its token and the hash of the binding secret of its session. The answer is
/// the proved identity when the token is valid and its session is alive and is still the token's, null otherwise.
/// <para>
/// The answer is the Authentication Center's statement, received from it: it is the one case where an
/// <see cref="IAuthenticationInfoPoco"/> becomes a trusted authentication (a party without the keys of the Authentication
/// Center can't read the token itself). Internal to the System and executed by the receiving endpoint only.
/// </para>
/// </summary>
[Internal]
public interface IVerifyCallerProofCommand : ICommand<IAuthenticationInfoPoco?>, ICommandEndpointOnly
{
    /// <summary>
    /// Gets or sets the user's token.
    /// </summary>
    string Token { get; set; }

    /// <summary>
    /// Gets or sets the hash of the binding secret presented with the token.
    /// </summary>
    string BindingSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the header of the seal of the routed command that carried the proof (the asking party is its
    /// destination), or null for a proof received directly. With <see cref="RoutedPayloadDigest"/> and
    /// <see cref="RoutedSignature"/>, the Authentication Center verifies that the party that opened the session sealed the
    /// command, without the command itself.
    /// </summary>
    byte[]? RoutedSeal { get; set; }

    /// <summary>
    /// Gets or sets the digest of the bytes of the routed command (see <see cref="RoutedSeal"/>).
    /// </summary>
    byte[]? RoutedPayloadDigest { get; set; }

    /// <summary>
    /// Gets or sets the signature of the <see cref="RoutedSeal"/>.
    /// </summary>
    byte[]? RoutedSignature { get; set; }
}
