namespace CK.AppIdentity.KeyManagement
{
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
        /// the remote reply. 
        /// </summary>
        Always
    }
}
