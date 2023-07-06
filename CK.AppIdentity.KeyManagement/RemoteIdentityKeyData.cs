using CK.Core;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Data only key (no computing capabilities).
    /// <para>
    /// This implements <see cref="IEquatable{T}"/> for any kind of <see cref="IPublicKeyData"/>.
    /// </para>
    /// </summary>
    public sealed class RemoteIdentityKeyData : IPublicKeyData, IEquatable<IPublicKeyData>
    {
        readonly PublicKey _publicKey;
        readonly byte[] _publicRaw;
        readonly string _name;
        readonly DateTime _timeName;

        /// <summary>
        /// Initializes a remote public key data.
        /// </summary>
        /// <param name="timeName">The key's time name.</param>
        /// <param name="publicKey">The public key.</param>
        public RemoteIdentityKeyData( DateTime timeName, PublicKey publicKey )
        {
            Throw.CheckNotNullArgument( publicKey );
            Throw.CheckArgument( timeName.Kind == DateTimeKind.Utc );
            _name = timeName.ToString( FileUtil.FileNameUniqueTimeUtcFormat );
            _timeName = timeName;
            _publicKey = publicKey;
            _publicRaw = publicKey.ExportSubjectPublicKeyInfo();
        }

        /// <summary>
        /// Initializes a remote public key data from a <see cref="LocalIdentityKey"/>.
        /// </summary>
        /// <param name="localIdentity">A local identity.</param>
        public RemoteIdentityKeyData( LocalIdentityKey localIdentity )
        {
            Throw.CheckNotNullArgument( localIdentity );
            _name = localIdentity.Name;
            _timeName = localIdentity.TimeName;
            _publicKey = localIdentity.PublicKey;
            _publicRaw = localIdentity._publicRaw;
        }

        /// <inheritdoc />
        public PublicKey PublicKey => _publicKey;

        /// <inheritdoc />
        public ReadOnlyMemory<byte> PublicKeyRawData => _publicRaw;

        /// <inheritdoc />
        public string Name => _name;

        /// <inheritdoc />
        public DateTime TimeName => _timeName;

        /// <summary>
        /// Challenges <see cref="IPublicKeyData.TimeName"/> and <see cref="IPublicKeyData.PublicKeyRawData"/>.
        /// <para>
        /// The <paramref name="other"/> must be a non null <see cref="RemoteIdentityKey"/>,
        /// <see cref="RemoteIdentityKeyData"/> or <see cref="LocalIdentityKey"/>.
        /// Any other implementation of <see cref="IPublicKeyData"/> will never be equal to this.
        /// </para>
        /// </summary>
        /// <param name="other">The other key to test.</param>
        /// <returns>True if the public key data is the same as this one.</returns>
        public bool Equals( IPublicKeyData? other )
        {
            return other != null
                    && _timeName == other.TimeName
                    && _publicRaw.AsSpan().SequenceEqual( other.PublicKeyRawData.Span )
                    && (other is RemoteIdentityKey || other is RemoteIdentityKeyData || other is LocalIdentityKey );
        }

        /// <summary>
        /// Checks whether the name and raw data are equals to the provided ones.
        /// </summary>
        /// <param name="timeName">The <see cref="TimeName"/>.</param>
        /// <param name="publicRawData">The <see cref="PublicKeyRawData"/>.</param>
        /// <returns>True if the provided data is the same as this one.</returns>
        public bool Equals( DateTime timeName, Span<byte> publicRawData )
        {
            return _timeName == timeName && publicRawData.SequenceEqual( _publicRaw );
        }

        /// <inheritdoc />
        public void WriteFile( NormalizedPath fullPath )
        {
            File.WriteAllBytes( fullPath, _publicRaw );
        }

    }
}
