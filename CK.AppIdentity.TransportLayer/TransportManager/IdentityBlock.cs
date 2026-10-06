using CK.AppIdentity.KeyManagement;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// What <see cref="ZeroProtocol.ReadIdentityBlockAndVerify"/> read from a peer's identity block.
/// </summary>
/// <param name="Verdict">The verdict on the tail, against what we pin for the sender.</param>
/// <param name="Head">The head of the tail: the event that reveals the key that signed.</param>
/// <param name="HeadKeyData">The key the head reveals.</param>
/// <param name="HeadKey">The verifier of that key, when the signature was checked with it.</param>
/// <param name="StatedSeq">What the sender pins for us: the sequence, or null when it pins nothing.</param>
/// <param name="StatedDigest">What the sender pins for us: the event digest, or null.</param>
readonly record struct IdentityBlock( KeyChainVerdict Verdict,
                                      KeyEvent Head,
                                      RemoteIdentityKeyData HeadKeyData,
                                      RemoteIdentityKey? HeadKey,
                                      int? StatedSeq,
                                      byte[]? StatedDigest );
