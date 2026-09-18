using CK.Core;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Identity key exposed by <see cref="ILocalKeys.Identities"/>.
/// <para>
/// This is the party's certificate authority. It signs message transcripts itself
/// (<see cref="TrySignHash"/>) and issues the purpose-specific credentials anything else needs
/// (<see cref="CreateDerivedCertificate"/>). Its private key is never exposed: a caller that needs a
/// key of its own asks for one to be issued.
/// </para>
/// </summary>
public sealed class LocalIdentityKey : IPublicKeyData
{
    // RFC 5280 extension identifiers. These four describe the issuance rather than the purpose of
    // what is issued, so CreateDerivedCertificate owns them and refuses a caller that sets them.
    const string SubjectKeyIdentifierOid = "2.5.29.14";
    const string KeyUsageOid = "2.5.29.15";
    const string BasicConstraintsOid = "2.5.29.19";
    const string AuthorityKeyIdentifierOid = "2.5.29.35";

    readonly X509Certificate2 _certificate;
    readonly ECDsa _privateKey;
    readonly internal byte[] _publicRaw;
    readonly string _name;
    readonly DateTime _timeName;
    readonly DateTime _notAfter;
    readonly DateTime _notBefore;

    internal LocalIdentityKey( string name, DateTime timeName, X509Certificate2 certificate, ECDsa privateKey )
    {
        Throw.DebugAssert( timeName.Kind == DateTimeKind.Utc );
         Throw.DebugAssert( "This is important: key serialization uses the timeName.",
                            name == timeName.ToString( FileUtil.FileNameUniqueTimeUtcFormat ) );
        _certificate = certificate;
        _privateKey = privateKey;
        _publicRaw = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        _name = name;
        _timeName = timeName;
        _notAfter = certificate.NotAfter.ToUniversalTime();
        _notBefore = certificate.NotBefore.ToUniversalTime();
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
    /// Gets the date time from which this key is valid.
    /// </summary>
    public DateTime NotBefore => _notBefore;

    /// <summary>
    /// Gets the subject of this identity's certificate. <see cref="CreateDerivedCertificate"/> reuses
    /// it by default, so that a derived credential speaks for the same party.
    /// </summary>
    public X500DistinguishedName SubjectName => _certificate.SubjectName;

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

    /// <summary>
    /// Issues an end-entity certificate signed by this identity, carrying a freshly generated ECDSA
    /// key pair of its own. The caller owns the result and must dispose it.
    /// <para>
    /// This is how a credential is obtained for something that is not message signing — a mutual TLS
    /// channel being the first of them. The identity private key signs the new certificate and does
    /// not leave this object, so the credential can be scoped to one purpose, given a shorter life
    /// and thrown away without touching the identity that every remote has pinned. Handing out the
    /// identity key itself and letting each purpose use it directly is the weaker arrangement: one
    /// key for everything, nothing to revoke short of rotating the identity, and it has to cross
    /// every package boundary that needs it.
    /// </para>
    /// <para>
    /// The result is deliberately not cached here, since what a caller asks for is shaped by
    /// <paramref name="configure"/>. A caller minting per connection should hold its own cache keyed
    /// on <see cref="ILocalKeys.CurrentIdentity"/> — keyed on the identity, so that a rotation
    /// invalidates it instead of pinning a credential to a key that is on its way out.
    /// </para>
    /// </summary>
    /// <param name="subject">
    /// The subject of the new certificate. Defaults to <see cref="SubjectName"/>.
    /// </param>
    /// <param name="notAfter">
    /// UTC expiration, which must be inside this identity's own validity period. Defaults to
    /// <see cref="NotAfter"/>. A certificate outliving its issuer cannot be chain validated once the
    /// issuer expires, which is why this is bounded rather than silently clamped.
    /// </param>
    /// <param name="configure">
    /// Optional configuration of the request, for what the credential is FOR: extended key usages,
    /// subject alternative names. It must not set BasicConstraints or the Subject/Authority Key
    /// Identifier — those describe the issuance and are set here. Key Usage may be set; it defaults
    /// to <see cref="X509KeyUsageFlags.DigitalSignature"/>.
    /// </param>
    /// <returns>A new certificate with its private key.</returns>
    public X509Certificate2 CreateDerivedCertificate( X500DistinguishedName? subject = null,
                                                      DateTime? notAfter = null,
                                                      Action<CertificateRequest>? configure = null )
    {
        DateTimeOffset end;
        if( notAfter.HasValue )
        {
            var v = notAfter.Value;
            // The Kind is checked rather than converted. X509Certificate2.NotAfter/NotBefore are
            // LOCAL time, so a caller reading one of those and handing it here would shift the expiry
            // by the machine's UTC offset, up to 14 hours either way, and never hear about it.
            Throw.CheckArgument( "notAfter must be a UTC DateTime.", v.Kind == DateTimeKind.Utc );
            Throw.CheckArgument( "notAfter must be inside the issuing identity's validity period.",
                                 v > _notBefore && v <= _notAfter );
            end = new DateTimeOffset( v );
        }
        else
        {
            end = _certificate.NotAfter;
        }
        using( var ecdsa = ECDsa.Create() )
        {
            Throw.CheckState( "Unable to create ECDsa.", ecdsa != null );
            ecdsa.KeySize = 256;
            var request = new CertificateRequest( subject ?? _certificate.SubjectName, ecdsa, HashAlgorithmName.SHA256 );
            configure?.Invoke( request );

            // Refuse rather than overwrite or append: a certificate carrying two BasicConstraints is
            // one that some validators accept and others reject, which is the worst of both.
            CheckNotConfigured( request, BasicConstraintsOid, nameof( X509BasicConstraintsExtension ) );
            CheckNotConfigured( request, SubjectKeyIdentifierOid, nameof( X509SubjectKeyIdentifierExtension ) );
            CheckNotConfigured( request, AuthorityKeyIdentifierOid, nameof( X509AuthorityKeyIdentifierExtension ) );

            // CA:false, because this is a leaf. The issuing identity says pathLen 0, so a validator
            // would reject a CA here in any case — but a certificate should state what it is rather
            // than rely on the one above it to contradict it.
            request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: false,
                                                                                  hasPathLengthConstraint: false,
                                                                                  pathLengthConstraint: 0,
                                                                                  critical: true ) );
            if( !HasExtension( request, KeyUsageOid ) )
            {
                request.CertificateExtensions.Add( new X509KeyUsageExtension( X509KeyUsageFlags.DigitalSignature,
                                                                              critical: true ) );
            }
            // RFC 5280 4.2.1.2: conforming CAs MUST mark the Subject Key Identifier non-critical.
            request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, critical: false ) );
            // Key identifier only. Naming the issuer and serial as well would tie this certificate to
            // one certificate of the identity rather than to its key.
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate( _certificate,
                                                                          includeKeyIdentifier: true,
                                                                          includeIssuerAndSerial: false ) );

            // Serial numbers must be unique per issuer. Against the handful of certificates one
            // identity ever signs, 8 random bytes is a collision probability worth nothing.
            Span<byte> serialNumber = stackalloc byte[8];
            RandomNumberGenerator.Fill( serialNumber );
            // NotBefore is the issuer's: a window nested inside the issuer's is what a chain
            // validator expects, and this certificate has no reason to start any later.
            using( var cert = request.Create( _certificate, _certificate.NotBefore, end, serialNumber ) )
            {
                return cert.CopyWithPrivateKey( ecdsa );
            }
        }
    }

    static bool HasExtension( CertificateRequest request, string oid )
        => request.CertificateExtensions.Any( e => e.Oid?.Value == oid );

    static void CheckNotConfigured( CertificateRequest request, string oid, string name )
    {
        Throw.CheckArgument( $"configure must not add a {name}: it is set by CreateDerivedCertificate.",
                             !HasExtension( request, oid ) );
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
