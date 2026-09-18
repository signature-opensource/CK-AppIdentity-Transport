using CK.AppIdentity.KeyManagement;
using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Answers "was this certificate issued by that identity?" against a <em>bare public key</em>.
/// <para>
/// This exists because of a gap in the platform. A listener holds each remote's pinned identity as a
/// SubjectPublicKeyInfo and nothing more — distributing the identity <em>certificate</em> is the
/// format change the design deliberately did not make. But <see cref="X509Chain"/> can only validate
/// against an <see cref="X509Certificate2"/>, and net8.0 offers no way to verify a certificate's
/// signature against a key on its own. So the signature is checked directly: a certificate is a
/// SEQUENCE of the signed body, the algorithm, and the signature over that body, and all three are
/// readable without reconstructing anything.
/// </para>
/// <para>
/// What this is NOT: a chain validator. It checks one signature and nothing else — not validity
/// dates, not basic constraints, not key usage, not revocation. That is the right scope here, because
/// the answer is used to look up which remote is connecting and is then held against the signed
/// InitialMessage. A certificate that verifies but is expired still has to survive that, and a
/// certificate that does not verify simply leaves the connection on the path it would have taken
/// anyway. Do not reuse this where a real chain verdict is wanted.
/// </para>
/// </summary>
public static class IdentityIssuance
{
    // ecdsa-with-SHA256. The only algorithm CreateDerivedCertificate signs with; anything else is
    // not one of ours and is not worth guessing about.
    const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";

    /// <summary>
    /// Gets the Subject Key Identifier an identity's certificate carries, so that a leaf's Authority
    /// Key Identifier can be matched against it.
    /// <para>
    /// This is a cheap filter, not evidence: an Authority Key Identifier is unauthenticated and any
    /// peer can write whatever it likes there. Its only job is to pick one candidate out of a list so
    /// that an unauthenticated connection costs ONE signature verification instead of one per party —
    /// which on a listener serving a large fleet is the difference between a lookup and an
    /// amplifier. A forged value selects a candidate whose signature check then fails, and the
    /// connection falls through to the path it would have taken with no certificate at all.
    /// </para>
    /// </summary>
    public static string GetKeyIdentifier( IPublicKeyData identity )
    {
        // Built with the same type that minted it, so the two cannot drift apart over the choice of
        // hash or over what exactly is hashed.
        return new X509SubjectKeyIdentifierExtension( identity.PublicKey, critical: false ).SubjectKeyIdentifier!;
    }

    /// <summary>
    /// Gets the key identifier a certificate names as its issuer, or null when it names none.
    /// </summary>
    public static string? TryGetAuthorityKeyIdentifier( X509Certificate2 certificate )
    {
        foreach( var e in certificate.Extensions )
        {
            if( e is X509AuthorityKeyIdentifierExtension aki && aki.KeyIdentifier.HasValue )
            {
                return Convert.ToHexString( aki.KeyIdentifier.Value.Span );
            }
        }
        return null;
    }

    /// <summary>
    /// Verifies that <paramref name="certificate"/> carries a signature made by <paramref name="identity"/>.
    /// </summary>
    /// <returns>True when the identity's key signed this certificate.</returns>
    public static bool WasIssuedBy( X509Certificate2 certificate, IPublicKeyData identity )
    {
        try
        {
            if( !TrySplit( certificate.RawData, out var signedBody, out var algorithmOid, out var signature ) ) return false;
            if( algorithmOid != EcdsaWithSha256 ) return false;
            using var key = identity.PublicKey.GetECDsaPublicKey();
            if( key == null ) return false;
            // The signature inside a certificate is the DER SEQUENCE { r, s } of RFC 3279, not the
            // fixed-width r‖s the Zero Protocol uses for its own signatures. Passing the wrong format
            // here fails closed, which is why it is stated rather than defaulted.
            return key.VerifyData( signedBody.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence );
        }
        catch( Exception )
        {
            // Malformed input from an unauthenticated peer is an ordinary event here, and the answer
            // to all of it is the same: this is not a certificate that identity issued.
            return false;
        }
    }

    /// <summary>
    /// Splits a certificate into the bytes that were signed, the signature algorithm, and the
    /// signature. <c>Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }</c>
    /// (RFC 5280 §4.1), where what is signed is the complete encoding of <c>tbsCertificate</c>, tag
    /// and length included.
    /// </summary>
    static bool TrySplit( ReadOnlyMemory<byte> der,
                          out ReadOnlyMemory<byte> signedBody,
                          out string algorithmOid,
                          out byte[] signature )
    {
        signedBody = default;
        algorithmOid = string.Empty;
        signature = Array.Empty<byte>();

        var outer = new AsnReader( der, AsnEncodingRules.DER );
        var certificate = outer.ReadSequence();
        signedBody = certificate.ReadEncodedValue();
        var algorithm = certificate.ReadSequence();
        algorithmOid = algorithm.ReadObjectIdentifier();
        signature = certificate.ReadBitString( out int unusedBitCount );
        return unusedBitCount == 0 && signature.Length > 0;
    }
}
