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
    /// The schedule never approaches it: one key is issued per <see cref="AllowedOfflineDays"/> and
    /// lives twice that, so exactly two are valid at any time. Reaching this number means a restored
    /// or merged store, a hand-copied key, or a clock that moved backwards; the builder then keeps
    /// the most recent ones, trashes the rest and says so.
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
    /// So it is also the rotation period and, with it, how long a retired key keeps being accepted:
    /// a key is replaced once it has less than this left, and the one it replaces stays valid for
    /// another span of the same length. Two keys are valid at a time, whatever
    /// <see cref="MaxIdentityCount"/> allows. The trade this single number makes is how long a party
    /// may be unreachable without losing its identity, against how often it rotates.
    /// </para>
    /// <para>
    /// <b>It does not bound a stolen key.</b> This governs what this party SIGNS with. A verifier
    /// holds a <see cref="RemoteIdentityKey"/>, which carries no validity window at all and is never
    /// checked against one (see <see cref="RemoteIdentityKey"/>, where that choice is stated): a key
    /// stolen years ago stays a usable trust anchor for anyone still pinning it, and can rotate trust
    /// onto the thief's key through the normal renewal path. Shortening this shortens nothing for
    /// them. Revocation is an operator action - clear the remote's <c>TrustedIdentity</c>.
    /// </para>
    /// </summary>
    int AllowedOfflineDays { get; }

    /// <summary>
    /// Gets the current identity key (the first one of <see cref="Identities"/>).
    /// </summary>
    LocalIdentityKey CurrentIdentity { get; }

    /// <summary>
    /// Gets the identity keys. The first one is the current one,
    /// the other ones are still valid but obsolete.
    /// </summary>
    IReadOnlyList<LocalIdentityKey> Identities { get; }

    /// <summary>
    /// Gets a data protector for this party.
    /// This should be used to protect tokens-like data (small blocks).
    /// </summary>
    IDataProtector Protector { get; }
}
