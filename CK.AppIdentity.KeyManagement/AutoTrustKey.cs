namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Optional behavior that allows the <see cref="IRemoteKeys.TrustedIdentity"/> to be initialized or updated implicitly.
/// <para>
/// This allows remotes to be operational immediately by trusting the replied identity,
/// avoiding the step to enlist the remote's identity.
/// This is a "dangerous" option: it defaults to <see cref="Never"/>.
/// </para>
/// </summary>
public enum AutoTrustKey
{
    /// <summary>
    /// The <see cref="IRemoteKeys.TrustedIdentity"/> must always be set explicitly.
    /// </summary>
    Never,

    /// <summary>
    /// The <see cref="IRemoteKeys.TrustedIdentity"/> can be automatically initialized from
    /// the remote reply but only if nothing is pinned: trust on first use.
    /// <para>
    /// There is deliberately no "always" option. Once a pin exists, it moves only through rotations the
    /// remote committed to beforehand, or by an operator: accepting an unrelated identity over a pin is
    /// not a renewal but a takeover, and no configuration should be able to make it automatic.
    /// </para>
    /// </summary>
    Once
}
