using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Checks that a certificate was issued by an identity key, given only that key's public part.
/// <para>
/// .NET chain building wants the issuer as an <see cref="X509Certificate2"/>, and what a peer pins is a
/// bare key. So this reads the certificate's own encoding — <c>SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue }</c> — and verifies the signature over the signed body directly.
/// It is shared by the operational credentials of the Zero Protocol and the mTLS reverse lookup.
/// </para>
/// </summary>
public static class DerivedCertificateVerifier
{
    // ecdsa-with-SHA256. The only algorithm LocalIdentityKey.CreateDerivedCertificate signs with;
    // anything else is not one of ours and is not worth guessing about.
    const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";

    /// <summary>
    /// Gets whether <paramref name="certificate"/> carries a valid signature by the key whose
    /// SubjectPublicKeyInfo is <paramref name="issuerSpki"/>. Never throws: malformed input from an
    /// unauthenticated peer is an ordinary event, and the answer to all of it is "no".
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="issuerSpki">The issuer's SubjectPublicKeyInfo.</param>
    /// <returns>True if the certificate was signed by that key.</returns>
    public static bool IsIssuedBy( X509Certificate2 certificate, ReadOnlySpan<byte> issuerSpki )
    {
        try
        {
            if( !TrySplit( certificate.RawData, out var signedBody, out var algorithmOid, out var signature ) ) return false;
            if( algorithmOid != EcdsaWithSha256 ) return false;
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo( issuerSpki, out int read );
            if( read != issuerSpki.Length ) return false;
            // The signature inside a certificate is the DER SEQUENCE { r, s } of RFC 3279, not the
            // fixed-width r‖s the Zero Protocol uses for its own signatures. Passing the wrong format
            // here fails closed, which is why it is stated rather than defaulted.
            return key.VerifyData( signedBody.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence );
        }
        catch( Exception )
        {
            return false;
        }
    }

    static bool TrySplit( ReadOnlyMemory<byte> der,
                          out ReadOnlyMemory<byte> signedBody,
                          out string algorithmOid,
                          out byte[] signature )
    {
        var outer = new AsnReader( der, AsnEncodingRules.DER );
        var certificate = outer.ReadSequence();
        signedBody = certificate.ReadEncodedValue();
        var algorithm = certificate.ReadSequence();
        algorithmOid = algorithm.ReadObjectIdentifier();
        signature = certificate.ReadBitString( out int unusedBitCount );
        return unusedBitCount == 0 && signature.Length > 0;
    }
}
