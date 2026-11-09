using CK.AppIdentity.Cris;

namespace CK.Auth;

/// <summary>
/// Extends the <see cref="ICrisCallEnvelope"/> with the user's proof: the token and the hash of the binding secret
/// presented to the sending endpoint by the user (an interactive request). A deferred execution has no proof.
/// <para>
/// A proof is a bearer credential: it must never leave the System (the parties of the same domain and environment),
/// where any party can have it verified by its authentication center.
/// </para>
/// </summary>
public interface IAuthenticationCallEnvelope : ICrisCallEnvelope
{
    /// <summary>
    /// Gets or sets the user's token.
    /// </summary>
    string? Token { get; set; }

    /// <summary>
    /// Gets or sets the hash of the binding secret presented with the token.
    /// </summary>
    string? BindingSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the header of the seal of a routed command: the proof of a routed command is valid only with the
    /// seal of the party that opened the user's session (the authentication center package defines it). Null for a
    /// command sent to its destination directly.
    /// </summary>
    byte[]? RoutedSeal { get; set; }

    /// <summary>
    /// Gets or sets the signature of the <see cref="RoutedSeal"/>.
    /// </summary>
    byte[]? RoutedSignature { get; set; }
}
