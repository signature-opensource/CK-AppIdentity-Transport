using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// What an <see cref="IdentityAlert"/> is about.
/// </summary>
public enum IdentityAlertKind
{
    /// <summary>
    /// A remote pins this party at a sequence beyond its own log: someone rotated this identity, which
    /// requires the committed next key. The identity is taken over.
    /// </summary>
    IdentityTakenOver,

    /// <summary>
    /// A remote pins, at a sequence this party holds, an event that is not this party's: someone forked
    /// this identity, which requires that sequence's committed key.
    /// </summary>
    IdentityForked,

    /// <summary>
    /// A remote's chain has a fork: two validly signed events at the same sequence. Only the holder of
    /// that remote's committed key can produce one: the remote's identity is compromised.
    /// </summary>
    RemoteDuplicity,

    /// <summary>
    /// This party's next identity key is missing, or is not the one its log committed to: it can
    /// neither rotate nor be revoked.
    /// </summary>
    NextKeyLost,

    /// <summary>
    /// A scheduled rotation of this party could not happen.
    /// </summary>
    RotationFailing
}

/// <summary>
/// A security alert about an identity: something a human must know, even when everything keeps working.
/// <para>
/// This is deliberately not a peering issue. A peering issue says why a connection cannot be made and
/// clears when it can; an alert says that an identity is in doubt, and stays until someone
/// <see cref="ILocalKeys.Acknowledge">acknowledges</see> it, across restarts.
/// </para>
/// <para>
/// Alerts are deduplicated on (<see cref="Kind"/>, <see cref="Subject"/>, <see cref="Seq"/>,
/// <see cref="ObservedDigest"/>): a repetition updates <see cref="Count"/>, <see cref="LastSeen"/> and
/// <see cref="ReportedBy"/> rather than creating another alert. This object is an immutable snapshot.
/// </para>
/// </summary>
public sealed class IdentityAlert
{
    /// <summary>
    /// The tag of every log entry about an alert, so that a log pipeline can page on it with no code.
    /// </summary>
    public static readonly CKTrait LogTag = ActivityMonitor.Tags.Register( "IdentityAlert" );

    internal IdentityAlert( string id,
                            IdentityAlertKind kind,
                            string subject,
                            bool isAboutSelf,
                            IReadOnlyList<string> reportedBy,
                            int seq,
                            ReadOnlyMemory<byte> expectedDigest,
                            ReadOnlyMemory<byte> observedDigest,
                            DateTime firstSeen,
                            DateTime lastSeen,
                            int count )
    {
        Id = id;
        Kind = kind;
        Subject = subject;
        IsAboutSelf = isAboutSelf;
        ReportedBy = reportedBy;
        Seq = seq;
        ExpectedDigest = expectedDigest;
        ObservedDigest = observedDigest;
        FirstSeen = firstSeen;
        LastSeen = lastSeen;
        Count = count;
    }

    /// <summary>
    /// Gets the identifier of this alert: stable across its repetitions and across restarts.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets what this alert is about.
    /// </summary>
    public IdentityAlertKind Kind { get; }

    /// <summary>
    /// Gets the full name of the party whose identity is concerned.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets whether <see cref="Subject"/> is the local party itself.
    /// </summary>
    public bool IsAboutSelf { get; }

    /// <summary>
    /// Gets the full names of the remotes whose signed statements raised this alert. Empty when the
    /// local party found it by itself.
    /// </summary>
    public IReadOnlyList<string> ReportedBy { get; }

    /// <summary>
    /// Gets the sequence number in the subject's key event log this alert is about.
    /// </summary>
    public int Seq { get; }

    /// <summary>
    /// Gets the digest of the event held for <see cref="Seq"/>, if any.
    /// </summary>
    public ReadOnlyMemory<byte> ExpectedDigest { get; }

    /// <summary>
    /// Gets the digest of the event presented or stated, if any.
    /// </summary>
    public ReadOnlyMemory<byte> ObservedDigest { get; }

    /// <summary>
    /// Gets when this was first seen (UTC).
    /// </summary>
    public DateTime FirstSeen { get; }

    /// <summary>
    /// Gets when this was last seen (UTC).
    /// </summary>
    public DateTime LastSeen { get; }

    /// <summary>
    /// Gets how many times this has been seen.
    /// </summary>
    public int Count { get; }

    /// <summary>
    /// Gets whether this is about the security of an identity (as opposed to its upkeep).
    /// </summary>
    public bool IsCritical => Kind is IdentityAlertKind.IdentityTakenOver or IdentityAlertKind.IdentityForked or IdentityAlertKind.RemoteDuplicity;

    /// <inheritdoc />
    public override string ToString()
        => $"{Kind} of '{Subject}' at #{Seq} (seen {Count} time(s), first {FirstSeen:u}{(ReportedBy.Count > 0 ? $", reported by {string.Join( ", ", ReportedBy )}" : "")})";
}
