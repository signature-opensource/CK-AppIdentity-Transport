using CK.Core;
using System;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Public key data (no computing capabilities).
    /// </summary>
    public interface IPublicKeyData
    {
        /// <summary>
        /// Gets the <see cref="PublicKey"/>.
        /// </summary>
        PublicKey PublicKey { get; }

        /// <summary>
        /// Gets the <see cref="PublicKey"/> raw data (cache of <see cref="PublicKey.ExportSubjectPublicKeyInfo()"/>).
        /// </summary>
        ReadOnlyMemory<byte> PublicKeyRawData { get; }

        /// <summary>
        /// Gets the "time name" of this key (in <see cref="DateTimeKind.Utc"/>): it is the creation time of the key.
        /// <para>
        /// This name is not intrinsically mandatory, but it helps analyzing and
        /// understanding the system.
        /// </para>
        /// </summary>
        DateTime TimeName { get; }

        /// <summary>
        /// Gets the name of this key: it is the <see cref="TimeName"/> in
        /// the format <see cref="CK.Core.FileUtil.FileNameUniqueTimeUtcFormat"/> and
        /// is the string used by the key store (whatever it is).
        /// <para>
        /// This name is not intrinsically mandatory, but it helps analyzing and
        /// understanding the system.
        /// </para>
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Creates or overwrites a file with this public key.
        /// </summary>
        /// <param name="fullPath">The target file path.</param>
        void WritePublicKeyFile( NormalizedPath fullPath );
    }
}
