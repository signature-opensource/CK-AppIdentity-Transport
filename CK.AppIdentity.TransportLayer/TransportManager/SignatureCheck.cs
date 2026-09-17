namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Result of the signature verification of a Zero Protocol message that carries identity keys.
/// <para>
/// This is deliberately NOT a boolean. A message whose signature "verifies" is not necessarily a
/// message from the party we think we are talking to: when our trusted key is absent from the
/// presented list — or when we have no trusted key for that remote yet — the only key available to
/// verify with is the one the sender supplied in that very message. Such a signature proves that
/// the sender holds <em>some</em> private key and nothing more: anyone can produce it.
/// </para>
/// <para>
/// Acting on a <see cref="SelfAsserted"/> message is what lets an on-path attacker switch a remote
/// off, deny an eviction or fake a protocol mismatch without holding any key material. Call sites
/// must therefore branch on this value rather than on "did it verify".
/// </para>
/// </summary>
public enum SignatureCheck
{
    /// <summary>
    /// The signature does not verify. The message must be discarded.
    /// </summary>
    Failed,

    /// <summary>
    /// The signature verifies, but only against a key the sender supplied in this same message:
    /// our trusted key was not among the presented ones, or we have no trusted key for this remote.
    /// <para>
    /// This authenticates nobody. It is a valid starting point for a trust-on-first-use decision
    /// (<see cref="KeyManagement.AutoTrustKey"/>, or an operator approving a <c>PeeringIssue</c>
    /// after comparing <see cref="KeyManagement.PublicKeyDataExtensions.GetFingerprint"/> out of band), but it
    /// must never on its own drive a state change such as switching a remote off.
    /// </para>
    /// </summary>
    SelfAsserted,

    /// <summary>
    /// The signature verifies against the key we already trust for this remote.
    /// This is the only value that authenticates the peer.
    /// </summary>
    Trusted
}
