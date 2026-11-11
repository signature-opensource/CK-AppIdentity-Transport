using CK.Core;
using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Asks the Authentication Center, along its "AuthCenter" route, to verify the user's proof of a command routed to the
/// asking party (the <see cref="Destination"/>): its token and the hash of the binding secret of its session, encrypted for
/// the Authentication Center (<see cref="EncryptedProof"/>: the hops never hold the proof), and the seal of the session
/// party. A party without a channel to the Authentication Center sends it: the session party's keys are known by the
/// Authentication Center only.
/// <para>
/// The answer crosses hops: it is a statement signed by the Authentication Center (see <see cref="IAuthCenterProofStatement"/>),
/// verified with its keys (its trust anchor): a hop can withhold it, not forge it. It binds the <see cref="Nonce"/> chosen by
/// the asking party.
/// </para>
/// </summary>
[Internal]
public interface IVerifyRoutedProofQCommand : ICommand<IAuthCenterProofStatement?>
{
    /// <summary>
    /// Gets or sets the full name of the asking party: the destination of the routed command that carried the proof.
    /// </summary>
    string Destination { get; set; }

    /// <summary>
    /// Gets or sets a random value chosen by the asking party (16 bytes): the statement binds it.
    /// </summary>
    byte[] Nonce { get; set; }

    /// <summary>
    /// Gets or sets the user's token and the hash of the binding secret presented with it, encrypted for the
    /// Authentication Center (its encryption key is its own statement, see <see cref="IGetRemoteEncryptionKeyQCommand"/>)
    /// with the <see cref="Destination"/> and the <see cref="Nonce"/> as associated data.
    /// </summary>
    byte[] EncryptedProof { get; set; }


    /// <summary>
    /// Gets or sets the header of the seal of the routed command.
    /// </summary>
    byte[] RoutedSeal { get; set; }

    /// <summary>
    /// Gets or sets the digest of the bytes of the routed command.
    /// </summary>
    byte[] RoutedPayloadDigest { get; set; }

    /// <summary>
    /// Gets or sets the signature of the <see cref="RoutedSeal"/> by the session party.
    /// </summary>
    byte[] RoutedSignature { get; set; }
}

/// <summary>
/// The statement of the Authentication Center that a routed user's proof is valid (see <see cref="IVerifyRoutedProofQCommand"/>):
/// the session is alive and still the token's, and the session party sealed the command for the destination.
/// </summary>
public interface IAuthCenterProofStatement : IPoco
{
    /// <summary>
    /// Gets or sets the encoded signature of the statement by the Authentication Center.
    /// </summary>
    byte[] Signature { get; set; }
}
