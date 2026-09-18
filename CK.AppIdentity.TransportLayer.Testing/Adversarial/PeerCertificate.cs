using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// A TLS certificate the adversarial peer presents, minted here rather than obtained from
/// <c>LocalIdentityKey.CreateDerivedCertificate</c>.
/// <para>
/// That independence is the point, the same way <see cref="PeerWire"/> is an independent codec. A
/// harness that used the production factory could only ever present certificates the production
/// factory is willing to produce, and the cases worth testing are exactly the ones it would refuse
/// to build: a certificate the peer does not attest, a second certificate swapped in, a credential
/// belonging to somebody else.
/// </para>
/// <para>
/// It also makes the transport's own claim checkable: nothing here chains to the peer's identity,
/// nothing is pinned, and a real peer still completes the TLS handshake with it — because under this
/// design TLS is not what decides who you are talking to.
/// </para>
/// </summary>
public sealed class PeerCertificate : IDisposable
{
    const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    PeerCertificate( X509Certificate2 certificate )
    {
        Certificate = certificate;
        Binding = BindingOf( certificate );
    }

    /// <summary>
    /// Creates a self-signed end-entity certificate with the two TLS extended key usages.
    /// </summary>
    /// <param name="commonName">The subject. It identifies nothing; it is what a capture displays.</param>
    public static PeerCertificate Create( string commonName = "AdversarialPeer" )
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.KeySize = 256;
        var request = new CertificateRequest( $"CN={commonName}", ecdsa, HashAlgorithmName.SHA256 );
        request.CertificateExtensions.Add( new X509KeyUsageExtension( X509KeyUsageFlags.DigitalSignature, critical: true ) );
        request.CertificateExtensions.Add( new X509BasicConstraintsExtension( false, false, 0, critical: true ) );
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension( new OidCollection { new Oid( ServerAuthOid ), new Oid( ClientAuthOid ) },
                                               critical: false ) );
        request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, critical: false ) );

        var now = DateTimeOffset.UtcNow;
        using var selfSigned = request.CreateSelfSigned( now.AddDays( -1 ), now.AddDays( 30 ) );
        // The same round-trip the production credential needs: a key attached in memory by
        // CreateSelfSigned has no container, and Schannel cannot sign with it.
        return new PeerCertificate( new X509Certificate2( selfSigned.Export( X509ContentType.Pkcs12 ) ) );
    }

    /// <summary>The certificate, with a private key a TLS stack can actually use.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// The truthful binding for this certificate: what an honest peer states about it in the signed
    /// handshake. A test that wants to lie passes something else.
    /// </summary>
    public byte[] Binding { get; }

    /// <summary>
    /// The SHA-256 of a certificate's DER — the harness's own computation of the value the protocol
    /// carries, so that a production bug cannot make both sides agree on the wrong number.
    /// </summary>
    public static byte[] BindingOf( X509Certificate certificate )
    {
        var binding = new byte[32];
        if( !certificate.TryGetCertHash( HashAlgorithmName.SHA256, binding, out int written ) || written != 32 )
        {
            throw new InvalidOperationException( $"Unable to hash '{certificate.Subject}'." );
        }
        return binding;
    }

    public void Dispose() => Certificate.Dispose();
}
