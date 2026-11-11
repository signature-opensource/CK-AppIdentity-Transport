using CK.Core;
using CK.PerfectEvent;
using System;
using Microsoft.AspNetCore.DataProtection;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// <see cref="ILocalParty"/> key management: handles the private keys
/// of the party.
/// </summary>
public interface ILocalKeys : IPartyKeys
{
    /// <summary>
    /// Default value of <see cref="MaxSignatureDays"/>.
    /// </summary>
    const int DefaultMaxSignatureDays = 7;
    /// <summary>
    /// Minimal number of days for <see cref="KeyRotationDays"/>.
    /// </summary>
    const int MinKeyRotationDays = 7;

    /// <summary>
    /// Maximal number of days for <see cref="KeyRotationDays"/>: ten years.
    /// <para>
    /// The value is scaled and handed to <c>DateTime.AddDays</c> to compute a certificate expiry, so
    /// leaving it unbounded lets a configuration typo throw out of the key builder and stop the
    /// service from starting at all, rather than being clamped and warned about.
    /// </para>
    /// </summary>
    const int MaxKeyRotationDays = 3650;

    /// <summary>
    /// Default value of <see cref="KeyRotationDays"/>.
    /// </summary>
    const int DefaultKeyRotationDays = 60;

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
    /// Default value of <see cref="OperationalKeyDays"/>.
    /// </summary>
    const int DefaultOperationalKeyDays = 7;

    /// <summary>
    /// Upper bound of <see cref="OperationalKeyDays"/>, and of the remaining validity a verifier
    /// accepts on a peer's credential, whatever that peer is configured with.
    /// </summary>
    const int MaxOperationalKeyDays = 31;

    /// <summary>
    /// Gets the lifetime, in days, of the <see cref="OperationalCredential"/> that signs this party's
    /// handshakes. It is renewed at half its life. A stolen operational key is worth at most this long.
    /// <para>
    /// Configured by "OperationalKeyDays" (1 to <see cref="MaxOperationalKeyDays"/>, default
    /// <see cref="DefaultOperationalKeyDays"/>).
    /// </para>
    /// </summary>
    int OperationalKeyDays { get; }

    /// <summary>
    /// Gets the longest a signature made by <see cref="Sign"/> can live, in days.
    /// <para>
    /// Configured by "MaxSignatureDays" (1 to <see cref="KeyRotationDays"/>, default
    /// <see cref="DefaultMaxSignatureDays"/>). A verifier accepts a credential valid for no more than its
    /// own <see cref="KeyRotationDays"/>, so a party whose signatures are checked by others must not be
    /// configured above theirs. It also bounds what the holder of a stolen key can still sign once the
    /// key has been replaced (DESIGN-key-pre-rotation §18.4).
    /// </para>
    /// </summary>
    int MaxSignatureDays { get; }

    /// <summary>
    /// Gets the local party.
    /// </summary>
    new ILocalParty Party { get; }

    /// <summary>
    /// Gets the checkpoint of the head of the key event log of this party: what another party configures as the trust
    /// anchor of this one (see <see cref="TrustAnchors"/>). It changes with each event (a rotation, a recovery, a
    /// decommission); it is logged at start and after each event.
    /// </summary>
    KeyCheckpoint Checkpoint { get; }

    /// <summary>
    /// Gets the trust anchors of this party, by the full name of the anchored party: a checkpoint of its key event log,
    /// given by the configuration ("Local:TrustAnchors:{FullName}"). An anchored party is verified from its checkpoint,
    /// never trusted on first use nor approved by an operator.
    /// </summary>
    IReadOnlyDictionary<string, KeyCheckpoint> TrustAnchors { get; }

    /// <summary>
    /// Finds the keys of an anchored party (by a checkpoint of <see cref="TrustAnchors"/> or by "#Dev"): its
    /// <see cref="IRemoteKeys"/> when it is a remote of this party, otherwise its entry in the key directory of this party
    /// (in memory: its events are obtained by any path, and verified from its anchor). Null when the party is not anchored.
    /// </summary>
    /// <param name="fullName">The full name of the anchored party.</param>
    /// <returns>Its keys, or null.</returns>
    IAnchoredKeys? FindAnchoredKeys( string fullName );

    /// <summary>
    /// Signs <paramref name="data"/> for the application, until <paramref name="expiration"/>.
    /// <para>
    /// Every verifier (<see cref="IPartyKeys.Verify"/>) refuses the signature after its expiration, and
    /// accepts it until then unless this identity is revoked: a regular rotation has no effect on it, a
    /// recovery condemns it. The signature is made by an application credential (its own key, issued by
    /// the identity key), which it contains.
    /// </para>
    /// </summary>
    /// <param name="purpose">
    /// What the signature is for, bound into it: a signature made for one purpose is refused for any
    /// other. Not empty, at most <see cref="ApplicationSignature.MaxPurposeLength"/> UTF-8 bytes.
    /// </param>
    /// <param name="data">The data to sign.</param>
    /// <param name="expiration">
    /// The expiration (UTC). Must be in the future and at most <see cref="MaxSignatureDays"/> ahead: it is
    /// never silently shortened.
    /// </param>
    /// <returns>The signature, with its credential.</returns>
    /// <exception cref="ArgumentException">When the purpose or the expiration is not valid.</exception>
    /// <exception cref="InvalidOperationException">When this party is decommissioned.</exception>
    ApplicationSignature Sign( string purpose, ReadOnlySpan<byte> data, DateTime expiration );

    /// <summary>
    /// Gets the rotation period of the identity key, in days. It also bounds the validity of the
    /// credentials and signatures this party accepts, and of its own signatures (MaxSignatureDays).
    /// <para>
    /// Identity keys are created with a lifetime that is twice this value (with a one day security).
    /// How long a party can stay offline is not this value: it is <see cref="KeyEventChain.MaxEventWindow"/>
    /// rotations (a remote further behind can't catch up from a handshake).
    /// </para>
    /// <para>
    /// The current key is replaced by the committed next one
    /// (<see cref="Rotate"/>) once its certificate has less than this left. This is checked at start and
    /// from the heartbeat, so a process that never restarts rotates like one that does.
    /// </para>
    /// <para>
    /// <b>It does not bound a stolen key by itself.</b> A verifier holds a <see cref="RemoteIdentityKey"/>,
    /// which carries no validity window. What bounds a stolen current key is the next rotation: a
    /// verifier that has seen it refuses the superseded key for handshakes. Revoking is rotating early.
    /// Application signatures are the exception: a regular rotation does not end them, and what a
    /// stolen replaced key can still sign is bounded by this value (see <see cref="ApplicationSignature"/>).
    /// </para>
    /// </summary>
    int KeyRotationDays { get; }

    /// <summary>
    /// Gets the current identity key.
    /// </summary>
    LocalIdentityKey CurrentIdentity { get; }

    /// <summary>
    /// Gets the current identity as one consistent snapshot: the key that signs and the tail of the
    /// log that proves it is current. What goes on the wire must come from one snapshot.
    /// </summary>
    LocalIdentityState State { get; }

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
    /// Takes the identity back with the recovery key: what to do after an
    /// <see cref="IdentityAlertKind.IdentityTakenOver"/> or <see cref="IdentityAlertKind.IdentityForked"/>
    /// alert, or when the next key is lost.
    /// <para>
    /// Writes a recovery event (revealing and signed by the recovery key the log committed to), then at
    /// once an ordinary rotation to a fresh online key, so the recovery key is needed for nothing else.
    /// Every remote that receives the tail drops whatever it had pinned since, including a chain moved
    /// with a stolen next key: ordinary events cannot change the recovery commitment, so the thief left
    /// it in place.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="recoveryKey">
    /// The recovery key, brought back from offline. Null when no "RecoveryPublicKey" was configured: the
    /// key is then in the key store.
    /// </param>
    /// <param name="nextRecoveryPublicKey">
    /// The SubjectPublicKeyInfo of the next recovery key, generated offline. Required when
    /// <paramref name="recoveryKey"/> is given; when it is not, a new one is created in the key store.
    /// </param>
    /// <returns>True on success, false (with an error logged) otherwise.</returns>
    bool Recover( IActivityMonitor monitor, System.Security.Cryptography.ECDsa? recoveryKey = null, ReadOnlyMemory<byte> nextRecoveryPublicKey = default );

    /// <summary>
    /// Gets the alerts not yet <see cref="Acknowledge">acknowledged</see>, oldest first. They survive
    /// restarts and are logged again at each start.
    /// </summary>
    IReadOnlyList<IdentityAlert> Alerts { get; }

    /// <summary>
    /// Raised for a new alert, and again when a new remote confirms one. Raised from the heartbeat that
    /// follows the detection. See also <see cref="KeyManagementFeatureDriver.AlertRaised"/>, which
    /// covers every local party.
    /// </summary>
    PerfectEvent<IdentityAlert> AlertRaised { get; }

    /// <summary>
    /// Raised when the key event log gains an event: a rotation, a recovery or a decommission. Raised from the heartbeat
    /// that follows the change, with the new <see cref="State"/> (its <see cref="LocalIdentityState.Tail"/> is what the
    /// remotes need to move their pin: the transport pushes it to the connected ones).
    /// </summary>
    PerfectEvent<LocalIdentityState> KeyEventAppended { get; }

    /// <summary>
    /// Gets the revoked identities: the entries of the last verified revocation list of the Authentication Center (set by
    /// <see cref="SetRevocationsAsync"/>). A remote whose log identity is revoked is refused at the peering (its pin is
    /// cleared), whatever it presents.
    /// </summary>
    IReadOnlyList<RevocationEntry> Revocations { get; }

    /// <summary>
    /// Gets whether a log identity is revoked (see <see cref="KeyEvent.GetIdentity"/>).
    /// </summary>
    /// <param name="identity">The identity of a log.</param>
    /// <returns>True when it is revoked.</returns>
    bool IsRevoked( ReadOnlySpan<byte> identity );

    /// <summary>
    /// Gets whether a full name is banned by the <see cref="Revocations"/>: a party revoked and not readmitted. It is
    /// refused in the routed commands and the routes (they carry full names).
    /// </summary>
    /// <param name="fullName">A full name.</param>
    /// <returns>True when it is banned.</returns>
    bool IsNameBanned( string fullName );

    /// <summary>
    /// Sets the revoked identities: the entries of a verified revocation list (the caller verified it). The pins of the
    /// revoked remotes are cleared, then <see cref="RevocationsChanged"/> is raised (the transport cuts their connections).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="entries">The entries.</param>
    /// <param name="cancel">Optional cancellation token.</param>
    /// <returns>The awaitable.</returns>
    Task SetRevocationsAsync( IActivityMonitor monitor, IReadOnlyList<RevocationEntry> entries, CancellationToken cancel = default );

    /// <summary>
    /// Raised by <see cref="SetRevocationsAsync"/>, with the new <see cref="Revocations"/>.
    /// </summary>
    PerfectEvent<IReadOnlyList<RevocationEntry>> RevocationsChanged { get; }

    /// <summary>
    /// Acknowledges an alert: it is removed and stops being logged at start. This does not fix what
    /// it reported: a condition that is still there raises it again.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="alert">The alert.</param>
    /// <returns>True if the alert was pending.</returns>
    bool Acknowledge( IActivityMonitor monitor, IdentityAlert alert );

    /// <summary>
    /// Judges what an authenticated remote states it pins for this party: an event digest at a
    /// sequence. A sequence beyond this party's log raises <see cref="IdentityAlertKind.IdentityTakenOver"/>;
    /// a digest that is not this party's event at that sequence raises <see cref="IdentityAlertKind.IdentityForked"/>.
    /// <para>
    /// The caller must only report statements of a remote it has authenticated: otherwise anyone could
    /// raise alerts about this party.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="reporter">The full name of the authenticated remote.</param>
    /// <param name="seq">The sequence the remote pins.</param>
    /// <param name="eventDigest">The digest of the event the remote pins.</param>
    /// <returns>True if an alert was raised.</returns>
    bool ReportPinStatement( IActivityLineEmitter logger, string reporter, int seq, ReadOnlySpan<byte> eventDigest );

    /// <summary>
    /// Gets a data protector for this party.
    /// This should be used to protect tokens-like data (small blocks).
    /// </summary>
    IDataProtector Protector { get; }

    /// <summary>
    /// Gets the current encryption key of this party, signed by it: what it publishes in its description (see
    /// <see cref="PartyDescription.EncryptionKey"/> and <see cref="PartyEncryption"/>). A new key is created when the
    /// current one ends in less than <see cref="PartyEncryption.KeyOverlap"/>: the key management re-announces the
    /// description then.
    /// </summary>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The published encryption key.</returns>
    PartyEncryptionKey GetEncryptionKey( DateTime utcNow );

    /// <summary>
    /// Finds a private encryption key of this party by its identifier (see <see cref="PartyEncryption.GetKeyId"/>): the
    /// current one, or a previous one that is still usable (see <see cref="PartyEncryption.KeyOverlap"/>).
    /// </summary>
    /// <param name="keyId">The identifier of the key.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The private key or null.</returns>
    System.Security.Cryptography.ECDiffieHellman? FindEncryptionKey( ReadOnlySpan<byte> keyId, DateTime utcNow );
}
