using CK.AppIdentity.KeyManagement;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The TLS credential a party presents, issued by its identity key.
/// <para>
/// The identity private key never reaches this package: it signs a certificate that carries a key
/// pair of its own (<see cref="LocalIdentityKey.CreateDerivedCertificate"/>). What is presented on
/// the wire is therefore a credential scoped to one purpose, which can be reissued or abandoned
/// without touching the identity that every remote has pinned.
/// </para>
/// <para>
/// The certificate does not identify anything by itself. Nothing checks who issued it: each side
/// states the hash of what it is presenting inside the signed Zero Protocol transcript, and that
/// statement is what binds the channel. The certificate exists because TLS needs one.
/// </para>
/// </summary>
sealed class TlsCredential
{
    const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    readonly object _lock;
    LocalIdentityKey? _identity;
    X509Certificate2? _certificate;
    byte[]? _binding;

    public TlsCredential()
    {
        _lock = new object();
    }

    /// <summary>
    /// Gets the certificate to present and the SHA-256 of its DER, reissuing them when the identity
    /// has rotated.
    /// <para>
    /// The cache is keyed on the identity instance rather than refreshed on a timer, so a rotation
    /// takes effect on the next connection instead of the next restart. The certificate it replaces
    /// is deliberately NOT disposed: a connection established a moment earlier still holds it for as
    /// long as it lives, and rotation happens at most once per <see cref="ILocalKeys.AllowedOfflineDays"/>.
    /// Reference counting every handshake to reclaim one certificate per rotation buys nothing that
    /// the finalizer does not.
    /// </para>
    /// </summary>
    public (X509Certificate2 Certificate, ReadOnlyMemory<byte> Binding) Get( ILocalKeys keys )
    {
        var current = keys.CurrentIdentity;
        lock( _lock )
        {
            if( !ReferenceEquals( _identity, current ) || _certificate == null )
            {
                using var issued = current.CreateDerivedCertificate( configure: r =>
                    r.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension( new OidCollection { new Oid( ServerAuthOid ), new Oid( ClientAuthOid ) },
                                                           critical: false ) ) );
                var c = MakeUsableBySslStream( issued );
                _binding = ComputeBinding( c );
                _certificate = c;
                _identity = current;
            }
            return (_certificate, _binding);
        }
    }

    /// <summary>
    /// Round-trips a freshly issued certificate through PKCS#12 so that a TLS stack can actually use
    /// its private key.
    /// <para>
    /// <c>CertificateRequest.Create</c> followed by <c>CopyWithPrivateKey</c> produces a certificate
    /// whose key is attached in memory rather than held in a key container. On Windows, Schannel
    /// cannot sign with such a key: the handshake fails with an <c>AuthenticationException</c> whose
    /// message is about credentials not being recognised, which points nowhere near the cause. The
    /// export and re-import give the key a container and cost one keygen-sized operation, once per
    /// identity rather than per connection.
    /// </para>
    /// <para>
    /// The PKCS#12 blob is passwordless and never leaves this method: it is a handle-shaped
    /// conversion, not a place the private key is stored.
    /// </para>
    /// </summary>
    static X509Certificate2 MakeUsableBySslStream( X509Certificate2 issued )
    {
        // A random password on the export/import pair, and the blob zeroed afterwards. Passwordless
        // PKCS#12 of a private key sitting in an unzeroed managed byte[] until the GC happens to
        // reuse the page is avoidable at no cost, even though the scope here is the derived TLS
        // credential and never the identity key.
        Span<byte> pwdBytes = stackalloc byte[32];
        RandomNumberGenerator.Fill( pwdBytes );
        var pwd = Convert.ToBase64String( pwdBytes );
        CryptographicOperations.ZeroMemory( pwdBytes );
        byte[]? blob = null;
        try
        {
            blob = issued.Export( X509ContentType.Pkcs12, pwd );
            return new X509Certificate2( blob, pwd );
        }
        finally
        {
            if( blob != null ) CryptographicOperations.ZeroMemory( blob );
        }
    }

    /// <summary>
    /// Computes what a peer states about a certificate: the SHA-256 of its DER.
    /// <para>
    /// Over the certificate rather than over the key it contains, because that is what both sides can
    /// answer for: <c>SslStream</c> hands out certificates, and a certificate is what anything
    /// terminating the channel has to present in place of the real one.
    /// </para>
    /// </summary>
    public static byte[] ComputeBinding( X509Certificate certificate )
    {
        var binding = new byte[Transport.CertificateBindingLength];
        if( !certificate.TryGetCertHash( HashAlgorithmName.SHA256, binding, out int written )
            || written != binding.Length )
        {
            throw new InvalidOperationException( $"Unable to compute the SHA-256 of '{certificate.Subject}'." );
        }
        return binding;
    }
}
