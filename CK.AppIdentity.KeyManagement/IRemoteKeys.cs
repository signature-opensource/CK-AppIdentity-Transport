using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// <see cref="IRemoteParty"/> public key management.
/// </summary>
public interface IRemoteKeys
{
    /// <summary>
    /// Default maximal allowed clock offset between parties is 5 minutes.
    /// </summary>
    public static readonly TimeSpan DefaultMaxClockOffset = TimeSpan.FromMinutes( 5 );

    /// <summary>
    /// Upper bound accepted for the "MaxClockOffset" configuration option (20 minutes).
    /// <para>
    /// Because no remote can be configured above it, a handshake nonce older than this can never be
    /// replayed against any remote — which is what lets the persisted replay cache drop stale
    /// entries when it is loaded.
    /// </para>
    /// </summary>
    public static readonly TimeSpan MaxAllowedClockOffset = TimeSpan.FromMinutes( 20 );

    /// <summary>
    /// Maximum number of handshake nonces retained per remote.
    /// <para>
    /// The replay cache is bounded by <see cref="MaxClockOffset"/>, not by this: an entry is dropped
    /// when it can no longer be replayed at all. This is only a memory guard, and a legitimate peer
    /// cannot approach it — the reconnect back-off caps attempts at roughly one per second, so even
    /// a 20 minute window holds around 1200 entries. Reaching it means a peer is handshaking
    /// abnormally fast, and the resulting loss is confined to that peer.
    /// </para>
    /// </summary>
    public const int MaxNonceCacheEntries = 4096;

    /// <summary>
    /// Gets the <see cref="IOwnedParty.Owner"/> party keys.
    /// </summary>
    ILocalKeys LocalKeys { get; }

    /// <summary>
    /// Gets the remote party.
    /// </summary>
    IRemoteParty Party { get; }

    /// <summary>
    /// Gets the "AutoTrustKey" configuration option.
    /// See <see cref="KeyManagement.AutoTrustKey"/>.
    /// </summary>
    AutoTrustKey AutoTrustKey { get; }

    /// <summary>
    /// Gets the "MaxClockOffset" configuration option.
    /// Defaults to <see cref="DefaultMaxClockOffset"/>.
    /// Cannot be less than 1 minute and greater than 20 minutes.
    /// </summary>
    TimeSpan MaxClockOffset { get; }

    /// <summary>
    /// Gets the trusted identity key: the key revealed by <see cref="TrustedEvent"/>.
    /// <para>
    /// When not null, an incoming connection must present a key event log that links to
    /// <see cref="TrustedEvent"/> and sign with the key at its head.
    /// </para>
    /// </summary>
    RemoteIdentityKey? TrustedIdentity { get; }

    /// <summary>
    /// Gets the pinned event of the remote's key event log, or null when nothing is trusted yet.
    /// <para>
    /// It moves forward only through rotations the remote committed to beforehand
    /// (<see cref="ApplyTail"/>), or by an operator (<see cref="SetTrustedIdentity"/>):
    /// holding the remote's current key is not enough to move it.
    /// </para>
    /// </summary>
    KeyEvent? TrustedEvent { get; }

    /// <summary>
    /// Gets whether the remote has decommissioned its identity: <see cref="TrustedEvent"/> is an
    /// abandonment, and nothing the remote sends is accepted any more.
    /// </summary>
    bool IsTerminated { get; }

    /// <summary>
    /// Pins an event, or clears the pin. This is the operator's action: approving the identity a
    /// remote presented, or pinning one handed over out of band. The event must be signed by the key
    /// it reveals, for this remote.
    /// This can be called by contexts that have no <see cref="IActivityMonitor"/>: this method accepts any <see cref="IActivityLineEmitter"/>
    /// instead of a classical monitor.
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="trusted">The event to pin, or null to clear the pin.</param>
    /// <returns>True if the pin has changed, false if it was already this one.</returns>
    bool SetTrustedIdentity( IActivityLineEmitter logger, KeyEvent? trusted );

    /// <summary>
    /// Verifies a tail of events the remote presented against <see cref="TrustedEvent"/> and applies
    /// the verdict, under one lock: a valid rotation advances the pin, an abandonment terminates it, a
    /// fork is stored as evidence and raises <see cref="IdentityAlertKind.RemoteDuplicity"/>.
    /// <para>
    /// An event proves itself, so a verified advance is kept whatever happens to the session that
    /// carried it.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="tail">The events presented, oldest first.</param>
    /// <returns>The verdict.</returns>
    KeyChainCheck ApplyTail( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> tail );

    /// <summary>
    /// Adopts a self-asserted head (one that does not link to a pin) when <see cref="AutoTrustKey"/>
    /// allows it: <see cref="AutoTrustKey.Once"/>, and only when nothing is pinned.
    /// <para>
    /// The caller must have verified that the head's key signed the message: this is a
    /// trust-on-first-use decision, not a proof.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="head">The head of the presented tail.</param>
    /// <returns>True if the head has been pinned.</returns>
    bool AdoptSelfAsserted( IActivityLineEmitter logger, KeyEvent head );

    /// <summary>
    /// Checks a clock offset against <see cref="MaxClockOffset"/>.
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="clockOffset">The offset to check.</param>
    /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
    /// <returns>True on success, false if the <paramref name="clockOffset"/> is out of range.</returns>
    bool CheckClockOffset( IActivityLineEmitter logger, TimeSpan clockOffset, LogLevel logLevel = LogLevel.Error );

    /// <summary>
    /// Checks that the provided <paramref name="nonceValue"/> is not already in the cache and adds it.
    /// Checking a nonce value always adds it to the cache. 
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="nonceValue">The nonce value to check and add.</param>
    /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
    /// <returns>True if the nonce has been added.</returns>
    bool CheckAndAddNonceValue( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error );

    /// <summary>
    /// Checks that the provided <paramref name="nonce"/> has a UTC creation time, is in range regarding <see cref="MaxClockOffset"/> and
    /// not already in the cache. Checking a potentially valid nonce always adds it to the cache. 
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="nonce">The nonce to check.</param>
    /// <param name="logLevel">Log level used to log the failure. Use <see cref="LogLevel.None"/> to not log anything.</param>
    /// <returns>True on success, false if this nonce is invalid, too old or already known.</returns>
    bool CheckNonce( IActivityLineEmitter logger, in TimedNonce nonce, LogLevel logLevel = LogLevel.Error );
}
