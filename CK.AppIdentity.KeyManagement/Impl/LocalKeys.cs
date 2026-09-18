using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CK.AppIdentity.KeyManagement;

sealed partial class LocalKeys : ILocalKeys
{
    const string PasswordExtension = ".pwd";
    readonly ILocalParty _local;
    readonly IDataProtector _protector;
    readonly int _allowedOfflineDays;
    // Key renewal should be implemented while running soon:
    // this is not readonly (Interlocked exchanged).
    // This must be an array (not the ImmutableArray) so that
    // reference equality can be used to detect changes.
    LocalIdentityKey[] _identities;

    LocalKeys( ILocalParty local,
               IDataProtector protector,
               LocalIdentityKey[] identities,
               int allowedOfflineDays )
    {
        _local = local;
        _identities = identities;
        _allowedOfflineDays = allowedOfflineDays;
        _protector = protector;
    }

    public ILocalParty Party => _local;

    public int AllowedOfflineDays => _allowedOfflineDays;

    public IDataProtector Protector => _protector;

    public LocalIdentityKey CurrentIdentity => _identities[0];

    public IReadOnlyList<LocalIdentityKey> Identities => _identities;

    internal void OnTearDown( IActivityMonitor monitor )
    {
        var identities = _identities;
        foreach( var key in identities )
        {
            key.OnTeardown();
        }
    }

    // Not used yet, and it can no longer be handed an identity certificate.
    //
    // Identity certificates are end-entity certificates: BasicConstraints CA:false and KeyUsage
    // DigitalSignature only. CertificateRequest.Create( issuerCertificate, ... ) verifies the issuer
    // and throws ArgumentException ("The issuer certificate does not have an appropriate value for
    // the Basic Constraints extension") for a non-CA signer — checked, it is not a silent no-op.
    //
    // So <paramref name="signer"/> must be a dedicated CA key. Making the identity key a CA to feed
    // this method is what this method's absent callers were paying for: a key that signs messages
    // AND asserts the authority to mint certificates, which signs anything if it ever reaches an OS
    // trust store. If a local-CA model is wanted, it needs its own key and its own lifecycle.
    internal static X509Certificate2 CreateSignedCertificate( string subjectName,
                                                              X509Certificate2 signer,
                                                              Action<CertificateRequest> configuration )
    {
        using( var ecdsa = ECDsa.Create() )
        {
            Throw.CheckState( "Unable to create ECDsa.", ecdsa != null );
            ecdsa.KeySize = 256;
            var request = new CertificateRequest( $"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256 );

            // Basic certificate constraints.
            request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: false, false, 0, true ) );
            // The AuthorityKeyIdentifier is the CA's subject key identifier.
            request.CertificateExtensions.Add( X509AuthorityKeyIdentifierExtension.CreateFromCertificate( signer,
                                                                                                          includeKeyIdentifier: true,
                                                                                                          includeIssuerAndSerial: false ) );

            configuration( request );

            // Let's use a 8 bytes random for the serial.
            Span<byte> serialNumber = stackalloc byte[8];
            RandomNumberGenerator.Fill( serialNumber );
            // Certificate expiry is the same as the identity one.
            using( var cert = request.Create( signer, signer.NotBefore, signer.NotAfter, serialNumber ) )
            {
                return cert.CopyWithPrivateKey( ecdsa );
            }
        }
    }
}
