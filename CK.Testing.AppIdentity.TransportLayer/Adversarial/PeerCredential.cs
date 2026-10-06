using CK.AppIdentity.KeyManagement;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// An operational credential the adversarial peer presents: a short-lived certificate issued by an
/// identity key, and the key that signs transcripts.
/// <para>
/// Built independently of the production <c>OperationalCredential</c> so that a test can issue what
/// production never would: another extended key usage, a CA, an expired or overlong one, or one
/// issued by a key that is not at the head of the presented log.
/// </para>
/// </summary>
public sealed class PeerCredential : IDisposable
{
    PeerCredential( byte[] encoded, ECDsa key )
    {
        Encoded = encoded;
        Key = key;
    }

    /// <summary>The DER of the certificate, as it travels on the wire.</summary>
    public byte[] Encoded { get; }

    /// <summary>The credential's key: what signs the transcript.</summary>
    public ECDsa Key { get; }

    /// <summary>
    /// Issues a credential with <paramref name="identityKey"/>.
    /// </summary>
    /// <param name="identityKey">The issuing identity key.</param>
    /// <param name="fullName">The party's name, for the subjects.</param>
    /// <param name="notBefore">Defaults to an hour ago.</param>
    /// <param name="notAfter">Defaults to seven days from now.</param>
    /// <param name="ekuOid">The extended key usage, null for none. Defaults to the transcript-signing one.</param>
    /// <param name="certificateAuthority">Whether the credential claims to be a CA.</param>
    public static PeerCredential Issue( ECDsa identityKey,
                                        string fullName,
                                        DateTime? notBefore = null,
                                        DateTime? notAfter = null,
                                        string? ekuOid = OperationalCredential.TranscriptSigningOid,
                                        bool certificateAuthority = false )
    {
        var nb = notBefore ?? DateTime.UtcNow.AddHours( -1 );
        var na = notAfter ?? DateTime.UtcNow.AddDays( 7 );

        var issuerRequest = new CertificateRequest( $"CN={Escape( fullName )}", identityKey, HashAlgorithmName.SHA256 );
        issuerRequest.CertificateExtensions.Add( new X509BasicConstraintsExtension( true, true, 0, true ) );
        issuerRequest.CertificateExtensions.Add( new X509KeyUsageExtension( X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true ) );
        issuerRequest.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( issuerRequest.PublicKey, false ) );
        using var issuer = issuerRequest.CreateSelfSigned( nb.AddDays( -1 ), na.AddDays( 1 ) );

        var key = ECDsa.Create( ECCurve.NamedCurves.nistP256 );
        var request = new CertificateRequest( $"CN={Escape( fullName )} (derived)", key, HashAlgorithmName.SHA256 );
        request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority, false, 0, true ) );
        request.CertificateExtensions.Add( new X509KeyUsageExtension( X509KeyUsageFlags.DigitalSignature, true ) );
        if( ekuOid != null )
        {
            request.CertificateExtensions.Add( new X509EnhancedKeyUsageExtension( new OidCollection { new Oid( ekuOid ) }, true ) );
        }
        request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, false ) );
        request.CertificateExtensions.Add( X509AuthorityKeyIdentifierExtension.CreateFromCertificate( issuer, true, false ) );
        using var cert = request.Create( issuer, nb, na, RandomNumberGenerator.GetBytes( 8 ) );
        return new PeerCredential( cert.RawData, key );
    }

    static string Escape( string value )
    {
        var b = new System.Text.StringBuilder( value.Length + 4 );
        foreach( var c in value )
        {
            if( ",+\"\\<>;#=".IndexOf( c ) >= 0 ) b.Append( '\\' );
            b.Append( c );
        }
        return b.ToString();
    }

    public void Dispose() => Key.Dispose();
}
