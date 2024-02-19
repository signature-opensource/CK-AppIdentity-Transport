using CK.Core;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement
{
    /// <summary>
    /// Identity key exposed by <see cref="ILocalKeys.Identities"/>.
    /// </summary>
    public sealed class LocalIdentityKey : IPublicKeyData
    {
        readonly X509Certificate2 _certificate;
        readonly ECDsa _privateKey;
        readonly internal byte[] _publicRaw;
        readonly string _name;
        readonly DateTime _timeName;
        readonly DateTime _notAfter;

        internal LocalIdentityKey( string name, DateTime timeName, X509Certificate2 certificate, ECDsa privateKey )
        {
            Throw.DebugAssert( timeName.Kind == DateTimeKind.Utc );
             Throw.DebugAssert( name == timeName.ToString( FileUtil.FileNameUniqueTimeUtcFormat ), "This is important: key serialization uses the timeName." );
            _certificate = certificate;
            _privateKey = privateKey;
            _publicRaw = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            _name = name;
            _timeName = timeName;
            _notAfter = certificate.NotAfter.ToUniversalTime();
        }

        /// <inheritdoc />
        public PublicKey PublicKey => _certificate.PublicKey;

        /// <inheritdoc />
        public ReadOnlyMemory<byte> PublicKeyRawData => _publicRaw;

        /// <inheritdoc />
        public string Name => _name;

        /// <inheritdoc />
        public DateTime TimeName => _timeName;

        /// <summary>
        /// Gets the expiration date time of this key.
        /// </summary>
        public DateTime NotAfter => _notAfter;

        /// <summary>
        /// Gets the size in bytes of the signature.
        /// </summary>
        public int SignatureSize => _privateKey.GetMaxSignatureSize( DSASignatureFormat.IeeeP1363FixedFieldConcatenation );

        /// <summary>
        /// Attempts to compute the ECDSA digital signature for the specified read-only span of bytes representing
        /// a data hash into the provided signature.
        /// </summary>
        /// <param name="hash">The hash for which a signature must be computed.</param>
        /// <param name="signature">The buffer to receive the signature.</param>
        /// <returns>false if destination is not long enough to receive the signature.</returns>
        public bool TrySignHash( ReadOnlySpan<byte> hash, Span<byte> signature, out int bytesWritten )
        {
            return _privateKey.TrySignHash( hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out bytesWritten );
        }

        /// <inheritdoc />
        public void WritePublicKeyFile( NormalizedPath fullPath )
        {
            File.WriteAllBytes( fullPath, _publicRaw );
        }

        /// <summary>
        /// Disposes the certificate and the internal private key.
        /// </summary>
        internal void OnTeardown()
        {
            _certificate.Dispose();
            _privateKey.Dispose();
        }
    }
}
