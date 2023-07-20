using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CK.AppIdentity.KeyManagement
{
    sealed partial class LocalKeys : ILocalKeys
    {
        private const string PasswordExtension = ".pwd";
        readonly ILocalParty _local;
        readonly IDataProtector _protector;
        readonly LocalNonceCache _nonceCache;
        LocalIdentityKey[] _identities;
        int _allowedOfflineDays;

        LocalKeys( ILocalParty local,
                   IDataProtector protector,
                   LocalIdentityKey[] identities,
                   LocalNonceCache nonceCache )
        {
            _local = local;
            _identities = identities;
            _nonceCache = nonceCache;
            _protector = protector;
            local.ApplicationIdentityService.Heartbeat.Sync += OnHeartbeat;
        }

        void OnHeartbeat( IActivityMonitor monitor, int callCount ) => _nonceCache.Save( monitor );

        public ILocalParty Party => _local;

        public int AllowedOfflineDays => _allowedOfflineDays;

        public IDataProtector Protector => _protector;

        public LocalIdentityKey CurrentIdentity => _identities[0];

        public IReadOnlyList<LocalIdentityKey> Identities => _identities;

        internal LocalNonceCache NonceCache => _nonceCache;

        internal void OnTearDown( IActivityMonitor monitor )
        {
            var identities = _identities;
            foreach( var key in identities )
            {
                key.OnTeardown();
            }
            _local.ApplicationIdentityService.Heartbeat.Sync -= OnHeartbeat;
            _nonceCache.Save( monitor );
        }

        // Not used yet.
        internal static X509Certificate2 CreateSignedCertificate( string subjectName, X509Certificate2 signer, Action<CertificateRequest> configuration )
        {
            using( var ecdsa = ECDsa.Create( "ECDsa" ) )
            {
                Throw.CheckState( "Unable to create ECDsa.", ecdsa != null );
                ecdsa.KeySize = 256;
                var request = new CertificateRequest( $"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256 );

                // Basic certificate constraints.
                request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: false, false, 0, true ) );
                // The AuthorityKeyIdentifier is the CA's subject key identifier.
                request.CertificateExtensions.Add( new X509AuthorityKeyIdentifierExtension( signer ) );

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
}
