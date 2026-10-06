using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// <see cref="ILocalParty"/> key management: handles the private keys
/// of the party.
/// </summary>
public interface ILocalKeys
{
    /// <summary>
    /// Minimal number of days for <see cref="AllowedOfflineDays"/>.
    /// </summary>
    const int MinAllowedOfflineDays = 7;

    /// <summary>
    /// Maximal number of days for <see cref="AllowedOfflineDays"/>: ten years.
    /// <para>
    /// The value is scaled and handed to <c>DateTime.AddDays</c> to compute a certificate expiry, so
    /// leaving it unbounded lets a configuration typo throw out of the key builder and stop the
    /// service from starting at all, rather than being clamped and warned about.
    /// </para>
    /// </summary>
    const int MaxAllowedOfflineDays = 3650;

    /// <summary>
    /// Default value of <see cref="AllowedOfflineDays"/>.
    /// </summary>
    const int DefaultAllowedOfflineDays = 60;

    /// <summary>
    /// The maximum count of simultaneously valid identity keys.
    /// <para>
    /// This is a protocol bound before it is a policy: a handshake carries every identity a party
    /// holds, and a peer refuses a longer list. It is enforced on both sides — a party whose store
    /// somehow held more would otherwise be refused by every remote at once, with the failure logged
    /// on the other side as invalid data coming from it.
    /// </para>
    /// <para>
    /// A party now holds a single identity key (see <see cref="Identities"/>): this bound remains only
    /// for the current wire format, which a peer checks, and goes with it.
    /// </para>
    /// </summary>
    const int MaxIdentityCount = 8;

    /// <summary>
    /// The maximum public key size (actual ECDsa public key sizes are far smaller).
    /// </summary>
    const int MaxPublicKeySize = 2048;

    /// <summary>
    /// Gets the local party.
    /// </summary>
    ILocalParty Party { get; }

    /// <summary>
    /// Gets the number of days during which this party or a remote party can be offline
    /// without losing their identities.
    /// <para>
    /// This drives the expiration delays of identity keys: identity keys are created with
    /// a lifetime that is twice this value (with a one day security).
    /// </para>
    /// <para>
    /// So it is also the rotation period: the current key is replaced by the committed next one
    /// (<see cref="Rotate"/>) once its certificate has less than this left.
    /// </para>
    /// <para>
    /// <b>It does not bound a stolen key by itself.</b> A verifier holds a <see cref="RemoteIdentityKey"/>,
    /// which carries no validity window. What bounds a stolen current key is the next rotation: a
    /// verifier that has seen it refuses the superseded key. Revoking is rotating early.
    /// </para>
    /// </summary>
    int AllowedOfflineDays { get; }

    /// <summary>
    /// Gets the current identity key.
    /// </summary>
    LocalIdentityKey CurrentIdentity { get; }

    /// <summary>
    /// Gets the identity keys: only <see cref="CurrentIdentity"/>. A rotation no longer needs the
    /// previous key to vouch for the new one (the key event log carries that), so there is no
    /// overlap any more. This remains for the current wire format, and a rotation replaces the list
    /// instance, which is how a change is detected.
    /// </summary>
    IReadOnlyList<LocalIdentityKey> Identities { get; }

    /// <summary>
    /// Gets the sequence number of the current identity key in the key event log.
    /// </summary>
    int Seq { get; }

    /// <summary>
    /// Gets the last events of the key event log (at most <see cref="KeyEventChain.MaxEventTail"/>),
    /// oldest first: what this party presents to prove which key is current.
    /// </summary>
    IReadOnlyList<KeyEvent> EventTail { get; }

    /// <summary>
    /// Gets whether this party has been <see cref="Decommission">decommissioned</see>.
    /// </summary>
    bool IsDecommissioned { get; }

    /// <summary>
    /// Replaces the current identity key by the one the log committed to, and commits to a new next
    /// one. <b>This is how a key is revoked</b>: by rotating early.
    /// <para>
    /// Only the committed next key can do this, so a thief holding the current key cannot.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>True on success, false (with an error logged) when the next key is unavailable.</returns>
    bool Rotate( IActivityMonitor monitor );

    /// <summary>
    /// Ends this identity for good: writes an abandonment event (signed by the committed next key)
    /// and destroys the keys. The party then refuses to start until its key store is reset, which
    /// starts a new identity that every remote has to approve.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>True on success, false (with an error logged) when the next key is unavailable or this is already decommissioned.</returns>
    bool Decommission( IActivityMonitor monitor );

    /// <summary>
    /// Gets a data protector for this party.
    /// This should be used to protect tokens-like data (small blocks).
    /// </summary>
    IDataProtector Protector { get; }
}
