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
    /// the remote reply but only if no trusted key was set. 
    /// </summary>
    Once,

    /// <summary>
    /// The <see cref="IRemoteKeys.TrustedIdentity"/> can be automatically accepted from
    /// the remote reply, every time, including when one is already pinned.
    /// <para>
    /// <b>This is not authentication in any form.</b> It is not "the remote renews its key": any peer
    /// that claims this remote's FullName and signs with a key of its own has that key adopted and
    /// persisted, replacing the pinned one permanently and locking the legitimate remote out. Nothing
    /// distinguishes the two cases, because there is nothing left to distinguish them WITH once the
    /// pinned key stops being required.
    /// </para>
    /// <para>
    /// It exists for bootstrapping and for environments where the transport is trusted by other
    /// means. Everywhere else, <see cref="Once"/> reduces the window to the first connection and
    /// <see cref="Never"/> closes it.
    /// </para>
    /// </summary>
    Always
}
