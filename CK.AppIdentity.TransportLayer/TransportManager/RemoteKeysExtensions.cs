using CK.AppIdentity.KeyManagement;
using CK.Core;

namespace CK.AppIdentity.TransportLayer;

static class RemoteKeysExtensions
{
    /// <summary>
    /// Must be called once identity keys have been read from a verified message incoming message:
    /// the <paramref name="foundTrustedKey"/> indicates whether our <see cref="IRemoteKeys.TrustedIdentity"/> has been
    /// found and the <paramref name="currentKeyData"/> is the current remote's identity.
    /// <list type="bullet">
    ///    <item>
    ///    If we have found our trusted key, we already trust him but its current remote key may have changed: we can
    ///    safely update it.
    ///    </item>
    ///    <item>
    ///    If we haven't found our trusted key (may be because we don't have one), we can avoid a manual enlistment of the remote
    ///    on our side: this depends on the <see cref="IRemoteKeys.AutoTrustKey"/> configuration. This is a "dangerous" option (it defaults to Never).
    ///    </item>
    /// </list>
    /// <para>
    /// This can be called by "back tasks" that have no <see cref="IActivityMonitor"/> in their context:
    /// this method accepts any <see cref="IActivityLineEmitter"/> instead of a classical monitor. 
    /// </para>
    /// </summary>
    /// <param name="logger">The logger to use.</param>
    /// <param name="foundTrustedKey">Whether our TrustedIdentity has been found in the message.</param>
    /// <param name="currentKeyData">Current remote's identity key data.</param>
    /// <param name="currentKey">The current key if it is known (already instantiated).</param>
    /// <returns>True if the <see cref="IRemoteKeys.TrustedIdentity"/> has been updated, false otherwise.</returns>
    public static bool OnReadIdentityKeys( this IRemoteKeys @this,
                                           IParallelLogger logger,
                                           bool foundTrustedKey,
                                           RemoteIdentityKeyData currentKeyData,
                                           RemoteIdentityKey? currentKey )
    {
        Throw.CheckArgument( currentKey == null || currentKey.Equals( currentKeyData ) );
        // This body used to be a verbatim copy of IRemoteKeys.ApplyReadTrustInfo, and only this copy
        // was ever called (L2). Two copies of the most security-sensitive decision in the codebase is
        // one too many — and the duplication hid that neither of them was safe to run concurrently,
        // which is what a remote's trust update actually does. The decision now lives with the state
        // it reads and writes, under that object's lock.
        return @this.ApplyReadTrustInfo( logger, new ReadTrustInfo( foundTrustedKey, currentKeyData, currentKey ) );
    }

    /// <summary>
    /// Applies <see cref="OnReadIdentityKeys"/> to a <see cref="SignatureCheck"/> and tells whether the
    /// message may be acted upon, that is whether the sender is authenticated as this remote.
    /// <para>
    /// This is the single place where "the signature verifies" becomes "this really is our remote".
    /// A <see cref="SignatureCheck.SelfAsserted"/> message is authenticated only if
    /// <see cref="IRemoteKeys.AutoTrustKey"/> just adopted the presented key — which is a
    /// trust-on-first-use decision, not a proof.
    /// </para>
    /// </summary>
    /// <param name="this">This remote keys.</param>
    /// <param name="logger">The logger to use.</param>
    /// <param name="check">The signature check result.</param>
    /// <param name="currentKeyData">Current remote's identity key data (null when the message was unsigned).</param>
    /// <param name="currentKey">The current key if it is known (already instantiated).</param>
    /// <returns>True if the message can be trusted, false if it must be discarded.</returns>
    public static bool IsTrustedAfterRead( this IRemoteKeys @this,
                                           IParallelLogger logger,
                                           SignatureCheck check,
                                           RemoteIdentityKeyData? currentKeyData,
                                           RemoteIdentityKey? currentKey )
    {
        if( check == SignatureCheck.Failed || currentKeyData == null ) return false;
        bool trusted = check == SignatureCheck.Trusted;
        // OnReadIdentityKeys returns true when it (re)set the TrustedIdentity: either our trusted key
        // was found and simply rotated, or AutoTrustKey adopted the presented one. In both cases the
        // remote is trusted from now on.
        trusted |= @this.OnReadIdentityKeys( logger, trusted, currentKeyData, currentKey );
        return trusted;
    }

}
