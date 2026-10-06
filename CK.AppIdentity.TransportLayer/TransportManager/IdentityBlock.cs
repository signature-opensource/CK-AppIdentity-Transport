using CK.AppIdentity.KeyManagement;
using System;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// What <see cref="ZeroProtocol.ReadIdentityBlockAndVerify"/> read from a peer's identity block.
/// </summary>
/// <param name="Verdict">The verdict on the tail, against what we pin for the sender.</param>
/// <param name="Head">The head of the tail: the event that reveals the sender's identity key.</param>
/// <param name="HeadKeyData">The identity key the head reveals.</param>
/// <param name="OperationalKey">The key of the sender's operational credential, when the signature verified with it.</param>
/// <param name="CredentialNotAfter">The expiry of that credential (UTC).</param>
/// <param name="StatedSeq">What the sender pins for us: the sequence, or null when it pins nothing.</param>
/// <param name="StatedDigest">What the sender pins for us: the event digest, or null.</param>
readonly record struct IdentityBlock( KeyChainVerdict Verdict,
                                      KeyEvent Head,
                                      RemoteIdentityKeyData HeadKeyData,
                                      ECDsa? OperationalKey,
                                      DateTime CredentialNotAfter,
                                      int? StatedSeq,
                                      byte[]? StatedDigest );
