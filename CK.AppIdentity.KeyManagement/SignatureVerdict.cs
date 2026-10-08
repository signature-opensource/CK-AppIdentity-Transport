namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The verdict of <see cref="IPartyKeys.Check"/>. The reason of a refusal is logged.
/// </summary>
public enum SignatureVerdict
{
    /// <summary>
    /// The signature is valid.
    /// </summary>
    Valid,

    /// <summary>
    /// The credential is issued by a key of the signer that this party doesn't know (yet): typically the signer
    /// rotated its key and this party is still pinned on the previous one, or nothing is pinned yet. Moving the pin
    /// (with the signer's last key events) may make it valid.
    /// </summary>
    UnknownIssuer,

    /// <summary>
    /// The signature is refused (expired, revoked, malformed, not matching its data...).
    /// </summary>
    Refused
}
