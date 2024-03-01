namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Encapsulates the result of multiple identities check against a <see cref="IRemoteKeys.TrustedIdentity"/>.
    /// This must be extracted from a digitally signed verified message.
    /// </summary>
    /// <param name="FoundTrustedKey">Whether our <see cref="IRemoteKeys.TrustedIdentity"/> has been found in the message.</param>
    /// <param name="CurrentKeyData">Current remote's identity key data.</param>
    /// <param name="CurrentKey">The current key if it is known (already instantiated).</param>
    public readonly record struct ReadTrustInfo( bool FoundTrustedKey, RemoteIdentityKeyData CurrentKeyData, RemoteIdentityKey? CurrentKey );

}
