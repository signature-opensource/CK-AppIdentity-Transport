namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Optional behavior that allows the <see cref="IRemoteKeys.TrustedIdentity"/> to be initialized or updated implicitly.
/// <para>
/// This allows remotes to be operational immediately by trusting the replied identity,
/// avoiding the step to enlist the remote's identity.
/// This is a "dangerous" option: it defaults to <see cref="Never"/>.
/// </para>
/// <para>
/// There are three ways to create the pin of a remote, from the strongest to the weakest:
/// <list type="number">
///   <item>A trust anchor (<see cref="ILocalKeys.TrustAnchors"/>, "Local:TrustAnchors:{FullName}"): the configuration
///   names a checkpoint of the remote's key event log, the remote is verified from it. This option is then ignored.</item>
///   <item>An approval by an operator (the enlistment, with the approval code): for a remote that is not known in
///   advance, with <see cref="Never"/>.</item>
///   <item><see cref="Once"/>: a trust on first use, a convenience. It protects against everything but the first
///   contact, exactly the gap that an anchor closes.</item>
/// </list>
/// </para>
/// </summary>
public enum AutoTrustKey
{
    /// <summary>
    /// The <see cref="IRemoteKeys.TrustedIdentity"/> must always be set explicitly: by a trust anchor, or by an operator
    /// (the approval of the enlistment).
    /// </summary>
    Never,

    /// <summary>
    /// The <see cref="IRemoteKeys.TrustedIdentity"/> can be automatically initialized from
    /// the remote reply but only if nothing is pinned: trust on first use.
    /// <para>
    /// The weak option: whoever answers first is trusted. Prefer a trust anchor for a remote known at deployment, and
    /// the enlistment (<see cref="Never"/>) for one that is not.
    /// </para>
    /// <para>
    /// There is deliberately no "always" option. Once a pin exists, it moves only through rotations the
    /// remote committed to beforehand, or by an operator: accepting an unrelated identity over a pin is
    /// not a renewal but a takeover, and no configuration should be able to make it automatic.
    /// </para>
    /// </summary>
    Once
}
