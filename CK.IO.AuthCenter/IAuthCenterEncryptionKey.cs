using CK.Core;

namespace CK.IO.AuthCenter;

/// <summary>
/// The public encryption key of an Authentication Center, signed by it for the "CK.AuthCenter.EncryptionKey" purpose:
/// a remote verifies it like a token before using it. The key must not be used after the expiration of its signature.
/// </summary>
public interface IAuthCenterEncryptionKey : IPoco
{
    /// <summary>
    /// Gets or sets the public key: the base64url of its SubjectPublicKeyInfo (ECDH P-256).
    /// </summary>
    string PublicKey { get; set; }

    /// <summary>
    /// Gets or sets the signature of the public key by the Authentication Center: the base64url of the encoded
    /// application signature. Its expiration is the end of use of the key.
    /// </summary>
    string Signature { get; set; }
}
