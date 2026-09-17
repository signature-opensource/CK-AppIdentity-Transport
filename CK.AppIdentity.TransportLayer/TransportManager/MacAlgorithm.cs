namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The message authentication primitive protecting run-phase frames.
/// <para>
/// Note there is deliberately no "None": the wire format must be incapable of expressing
/// "no MAC", so that no negotiation can ever select it.
/// </para>
/// </summary>
public enum MacAlgorithm : byte
{
    /// <summary>
    /// Not a valid selection. Exists only so that a zero byte on the wire is rejected rather than
    /// silently meaning something.
    /// </summary>
    Invalid = 0,

    /// <summary>
    /// AES-GMAC, the authentication-only mode of AES-GCM. The default: with AES-NI it runs at
    /// several GB/s, which is faster than HMAC-SHA256 on every CPU.
    /// <para>
    /// It requires a unique nonce per key, which this design guarantees structurally: keys are
    /// derived per connection from an ephemeral ECDH, separated per direction, and the nonce is
    /// built from a monotonic counter that cannot repeat within a connection.
    /// </para>
    /// </summary>
    AesGmac = 1,

    /// <summary>
    /// HMAC-SHA256 truncated to 128 bits. Used when the peer cannot run AES-GMAC in hardware.
    /// <para>
    /// The fault line is AES-NI, not SHA-NI: software AES is table-driven and carries cache-timing
    /// side channels, while SHA-256 has no such structure. On a machine without AES extensions
    /// HMAC is the better choice on both safety and, plausibly, speed.
    /// </para>
    /// </summary>
    HmacSha256 = 2
}
