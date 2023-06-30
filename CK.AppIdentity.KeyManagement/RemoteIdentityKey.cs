using CK.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Identity key exposed by <see cref="IRemoteKeys.TrustedIdentity"/>.
    /// <para>
    /// A remote key has no NotAfter expiration date because it is useless: a remote key
    /// is provided by a trusted remote and as long as it is provided, it can be used. Remote
    /// keys housekeeping is done automatically: the only persisted key is the most recent
    /// one provided by the remote. Moreover, a slightly expired key can still be used.
    /// </para>
    /// </summary>
    public sealed class RemoteIdentityKey : IPublicKeyData
    {
        readonly RemoteIdentityKeyData _keyData;
        readonly ECDsa _key;

        /// <summary>
        /// Initializes a remote public key.
        /// </summary>
        /// <param name="timeName">The key's time name.</param>
        /// <param name="publicKey">The public key.</param>
        public RemoteIdentityKey( RemoteIdentityKeyData keyData )
        {
            Throw.CheckNotNullArgument( keyData );
            var k = keyData.PublicKey.GetECDsaPublicKey();
            if( k == null ) Throw.ArgumentException( $"Unable to obtain the EDCsa key from public key data '{keyData.Name}'." );
            _key = k;
            _keyData = keyData;
        }

        /// <inheritdoc />
        public PublicKey PublicKey => _keyData.PublicKey;

        /// <inheritdoc />
        public ReadOnlyMemory<byte> PublicKeyRawData => _keyData.PublicKeyRawData;

        /// <inheritdoc />
        public string Name => _keyData.Name;

        /// <inheritdoc />
        public DateTime TimeName => _keyData.TimeName;

        /// <summary>
        /// Disposes the EDCsa verifier.
        /// </summary>
        internal void OnTeardown()
        {
            _key.Dispose();
        }
    }
}
