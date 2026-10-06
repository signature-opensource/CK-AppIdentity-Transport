using CK.Core;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// A short-lived key certified by the identity key: what signs every handshake (DESIGN-key-pre-rotation §5).
/// <para>
/// The identity key no longer signs transcripts: it certifies this key, at startup, after a rotation and
/// when this one reaches half its life. A stolen operational key therefore dies on its own within
/// <see cref="ILocalKeys.OperationalKeyDays"/>, with nobody having to notice the theft, and the identity
/// key is used rarely enough to live in hardware or offline.
/// </para>
/// <para>
/// The credential is an X.509 end-entity certificate issued by <see cref="LocalIdentityKey.CreateDerivedCertificate"/>:
/// <c>CA:false</c>, <c>DigitalSignature</c> and the <see cref="TranscriptSigningOid"/> extended key usage,
/// which no other credential of the identity carries (the mTLS one says server/client auth). A rotation
/// revokes every credential at once: they are verified against the key at the head of the presented log,
/// so anything issued by an earlier identity key no longer verifies.
/// </para>
/// </summary>
public sealed class OperationalCredential
{
    /// <summary>
    /// The extended key usage that marks a Zero Protocol transcript-signing credential. A UUID-based
    /// OID (ITU-T X.667, <c>2.25.{uuid}</c>): unique without a registration.
    /// </summary>
    public const string TranscriptSigningOid = "2.25.273626476421131706058242433793870924412";

    /// <summary>
    /// The upper bound of an encoded credential: what a peer can make us parse. An actual one is about 400 bytes.
    /// </summary>
    public const int MaxEncodedSize = 2048;

    readonly X509Certificate2 _certificate;
    readonly ECDsa _key;
    readonly byte[] _encoded;

    OperationalCredential( X509Certificate2 certificate, ECDsa key, DateTime issuedAt )
    {
        _certificate = certificate;
        _key = key;
        _encoded = certificate.RawData;
        IssuedAt = issuedAt;
        NotAfter = certificate.NotAfter.ToUniversalTime();
    }

    /// <summary>
    /// Gets the DER encoding of the certificate, as it travels on the wire.
    /// </summary>
    public ReadOnlyMemory<byte> Encoded => _encoded;

    /// <summary>
    /// Gets when this credential was issued (UTC): renewal happens at half its life.
    /// </summary>
    public DateTime IssuedAt { get; }

    /// <summary>
    /// Gets the expiry of this credential (UTC).
    /// </summary>
    public DateTime NotAfter { get; }

    /// <summary>
    /// Gets the size in bytes of the signature.
    /// </summary>
    public int SignatureSize => _key.GetMaxSignatureSize( DSASignatureFormat.IeeeP1363FixedFieldConcatenation );

    /// <summary>
    /// Signs a hash with this credential's key (IEEE P1363, r‖s).
    /// </summary>
    public bool TrySignHash( ReadOnlySpan<byte> hash, Span<byte> signature, out int bytesWritten )
        => _key.TrySignHash( hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out bytesWritten );

    /// <summary>
    /// Issues a credential for <paramref name="identity"/>, valid for <paramref name="days"/> from
    /// <paramref name="now"/> or until the identity's own expiry, whichever comes first.
    /// </summary>
    internal static OperationalCredential Issue( LocalIdentityKey identity, DateTime now, int days )
    {
        var notAfter = now.AddDays( days );
        if( notAfter > identity.NotAfter ) notAfter = identity.NotAfter;
        var cert = identity.CreateDerivedCertificate( notAfter: notAfter,
                                                      configure: r => r.CertificateExtensions.Add(
                                                          new X509EnhancedKeyUsageExtension( new OidCollection { new Oid( TranscriptSigningOid ) },
                                                                                             critical: true ) ) );
        var key = cert.GetECDsaPrivateKey();
        Throw.CheckState( "A credential just issued has its private key.", key != null );
        return new OperationalCredential( cert, key, now );
    }

    /// <summary>
    /// Verifies a credential presented by a peer and returns its key.
    /// </summary>
    /// <param name="encoded">The DER of the credential.</param>
    /// <param name="issuerSpki">The SPKI of the key at the head of the log the peer presented.</param>
    /// <param name="now">The current time (UTC).</param>
    /// <param name="maxClockOffset">The clock offset tolerated with this peer.</param>
    /// <param name="notAfter">Outputs the credential's expiry (UTC).</param>
    /// <param name="error">Outputs why the credential is refused, if it is.</param>
    /// <returns>The credential's public key, or null when it is refused.</returns>
    public static ECDsa? TryVerify( ReadOnlySpan<byte> encoded,
                                    ReadOnlySpan<byte> issuerSpki,
                                    DateTime now,
                                    TimeSpan maxClockOffset,
                                    out DateTime notAfter,
                                    out string? error )
    {
        notAfter = default;
        if( encoded.IsEmpty || encoded.Length > MaxEncodedSize )
        {
            error = "Credential size out of bounds.";
            return null;
        }
        X509Certificate2 c;
        try
        {
            c = X509CertificateLoader.LoadCertificate( encoded );
        }
        catch( Exception )
        {
            error = "Unreadable credential.";
            return null;
        }
        using( c )
        {
            if( !DerivedCertificateVerifier.IsIssuedBy( c, issuerSpki ) )
            {
                error = "The credential is not issued by the presented identity key.";
                return null;
            }
            if( c.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is not { } eku
                || !eku.EnhancedKeyUsages.Cast<Oid>().Any( o => o.Value == TranscriptSigningOid ) )
            {
                error = "The credential is not for transcript signing.";
                return null;
            }
            if( c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: false } )
            {
                error = "The credential must state CA:false.";
                return null;
            }
            if( c.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is not { } ku
                || (ku.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0 )
            {
                error = "The credential must allow DigitalSignature.";
                return null;
            }
            // X509Certificate2.NotBefore/NotAfter are LOCAL time: converted, never compared raw (M10).
            var notBefore = c.NotBefore.ToUniversalTime();
            notAfter = c.NotAfter.ToUniversalTime();
            if( now < notBefore - maxClockOffset )
            {
                error = $"The credential is not yet valid (NotBefore: {notBefore:u}).";
                return null;
            }
            if( now > notAfter + maxClockOffset )
            {
                error = $"The credential has expired (NotAfter: {notAfter:u}).";
                return null;
            }
            // Checked here, by the verifier: the bound is a property of what we accept, not of the
            // issuer's honesty or configuration. A credential inherits its issuer's NotBefore, so it is
            // the REMAINING validity that is bounded.
            if( notAfter > now.AddDays( ILocalKeys.MaxOperationalKeyDays ) + maxClockOffset )
            {
                error = $"The credential is valid for more than {ILocalKeys.MaxOperationalKeyDays} days.";
                return null;
            }
            var key = c.GetECDsaPublicKey();
            if( key == null || key.KeySize != 256 )
            {
                key?.Dispose();
                error = "The credential key must be ECDSA P-256.";
                return null;
            }
            error = null;
            return key;
        }
    }

    /// <summary>
    /// Disposes the key and the certificate.
    /// </summary>
    internal void OnTeardown()
    {
        _key.Dispose();
        _certificate.Dispose();
    }
}
