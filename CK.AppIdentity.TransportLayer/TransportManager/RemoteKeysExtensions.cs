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
        if( foundTrustedKey )
        {
            Throw.DebugAssert( @this.TrustedIdentity != null );
            // We trust the remote (we can update our trusted identity key).
            if( !@this.TrustedIdentity.Equals( currentKeyData ) )
            {
                logger.Info( $"Updating the remote '{@this.Party}' trusted key that has changed." );
                @this.SetTrustedIdentity( logger, currentKey ?? new RemoteIdentityKey( currentKeyData ) );
                return true;
            }
        }
        else
        {
            // We don't trust the remote. Depending on AutoTrustKey we may...
            if( @this.TrustedIdentity == null )
            {
                if( @this.AutoTrustKey != AutoTrustKey.Never )
                {
                    logger.Warn( $"Initializing the remote '{@this.Party}' trusted key because its '{nameof( AutoTrustKey )}' is {@this.AutoTrustKey}." );
                    @this.SetTrustedIdentity( logger, currentKey ?? new RemoteIdentityKey( currentKeyData ) );
                    return true;
                }
            }
            else
            {
                if( @this.AutoTrustKey == AutoTrustKey.Always )
                {
                    logger.Warn( $"Updating the remote '{@this.Party}' trusted key because its '{nameof( AutoTrustKey )}' is {@this.AutoTrustKey}." );
                    @this.SetTrustedIdentity( logger, currentKey ?? new RemoteIdentityKey( currentKeyData ) );
                    return true;
                }
            }
        }
        return false;
    }

}
