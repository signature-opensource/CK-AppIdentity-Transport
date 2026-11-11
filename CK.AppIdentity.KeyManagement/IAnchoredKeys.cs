using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The keys of an anchored party (a party with a trust anchor, see <see cref="ILocalKeys.TrustAnchors"/>), as a local
/// party holds them: its key event log verified from its anchor. Obtained by <see cref="ILocalKeys.FindAnchoredKeys"/>:
/// the <see cref="IRemoteKeys"/> of the anchored party when it is a remote, otherwise an entry of the key directory of the
/// local party, kept in memory, whose events come from any path (a routed query): they are verified, never believed.
/// </summary>
public interface IAnchoredKeys
{
    /// <summary>
    /// Gets the full name of the anchored party.
    /// </summary>
    string FullName { get; }

    /// <summary>
    /// Gets the head of the events held, null when none are held yet.
    /// </summary>
    KeyEvent? Head { get; }

    /// <summary>
    /// Gets the point of the anchored party's log from which its events are needed: the anchor (or the pin of a remote),
    /// or the head held by a directory entry. Null when the anchor can't be read yet (a "#Dev" anchor of a party that has
    /// not written its running status).
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <returns>The checkpoint, or null.</returns>
    KeyCheckpoint? GetStatedCheckpoint( IActivityLineEmitter logger );

    /// <summary>
    /// Applies events of the anchored party, from its anchor or from the head held: they must verify, otherwise nothing
    /// changes (a mismatch with the anchor is a <see cref="ActivityMonitor.Tags.SecurityCritical"/> error).
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="events">The consecutive events, oldest first (at most <see cref="KeyEventChain.MaxEventWindow"/>).</param>
    /// <returns>The verification.</returns>
    KeyChainCheck ApplyEvents( IActivityLineEmitter logger, IReadOnlyList<KeyEvent> events );

    /// <summary>
    /// Checks a signature made by the anchored party with <see cref="ILocalKeys.Sign"/> (see <see cref="IPartyKeys.Check"/>).
    /// <see cref="SignatureVerdict.UnknownIssuer"/> when nothing is held yet or when the signer rotated since the head held:
    /// its events must be obtained (and applied) first.
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="purpose">The purpose the signature was made for.</param>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>The verdict.</returns>
    SignatureVerdict Check( IActivityLineEmitter logger, string purpose, ReadOnlySpan<byte> data, in ApplicationSignature signature );
}
