using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CK.AppIdentity.KeyManagement;


sealed partial class LocalKeys 
{
    internal sealed class Builder : KeyLoader
    {
        readonly ILocalParty _local;
        readonly IDataProtectionProvider _protectionProvider;

        public Builder( ILocalParty local, IDataProtectionProvider protectionProvider )
            : base( local.LocalFileStore )
        {
            _local = local;
            _protectionProvider = protectionProvider;
        }

        public LocalKeys Build( IActivityMonitor monitor )
        {
            var protector = _protectionProvider.CreateProtector( _local.FullName.Path );
            int allowedOfflineDays = ReadAllowedOfflineDays( monitor );
            // KeyRenewalFrequency may be introduced to generate more certificates
            // but with shorter validity.
            int renewalFrequency = 1;

            var systemClock = _local.ApplicationIdentityService.SystemClock;
            var now = systemClock.UtcNow;
            var today = now.Date;
            var identityPath = _store.FolderPath.AppendPart( "Keys" );
            // File name matters:
            //   - The file name is in FileUtil.FileNameUniqueTimeUtcFormat format.
            //   - The date time parsed from the name is greater than now: This is our certificate name.
            //   - The certificates are sorted in reverse order of their certificate name.
            //   => The first one is the one to use, the current one, because it is the most recent one.
            List<LocalIdentityKey> identities = LoadIdentityKeys( monitor, protector, now, identityPath );
            // The certificate to consider is the last one of the list.
            // If it cannot guarantee the "AllowedOfflineDays", we must issue a new identity valid from now up to twice the AllowedOfflineDays: we (or a remote) can safely be offline for this time span.
            if( identities.Count == 0 || identities[0].NotAfter < today.AddDays( (allowedOfflineDays / renewalFrequency) + 1 ) )
            {
                var newOne = CreateIdentityCertificate( _local.FullName,
                                                        today.AddDays( ((renewalFrequency + 1) * allowedOfflineDays) / renewalFrequency ),
                                                        now );
                if( identities.Count == 0 ) monitor.Warn( $"No identity keys found in '{identityPath}'." );
                // Report the EXISTING key's expiry: that is the reason a new one is being created.
                // Printing newOne.NotAfter here would state the new key's expiry as the justification
                // for its own creation, which reads plausibly and tells an operator nothing.
                else monitor.Info( $"Most recent identity key ({identities[0].Name}.pfx) expires on {identities[0].NotAfter:yyyy-MM-dd}. " +
                                   $"It is not enough to guarantee AllowedOfflineDays = {allowedOfflineDays}." );

                var (name, filePath) = SaveIdentityFileAndPassword( monitor, protector, now, identityPath, newOne );

                // It's not a bad idea to reuse the validation here to obtain the private key.
                var privateKey = ValidateIdentityAndGetPrivateKey( monitor, now, filePath, newOne );
                if( privateKey == null )
                {
                    newOne.Dispose();
                    Throw.CKException( "A newly created key is not valid." );
                }
                else
                {
                    identities.Insert( 0, new LocalIdentityKey( name, now, newOne, privateKey ) );
                }
            }
            // We now have our identities, we can handle the public key files: any obsolete
            // keys are trashed, the current one is checked or created, only one public key file
            // is exposed.
            // Public key files are currently direct binary content of the public key (not a standard format).
            var ids = identities.ToArray();
            monitor.Info( $"Local '{_local.FullName}' has {ids.Length} identity keys. Current expires on {ids[0].NotAfter:yyyy-MM-dd}." );
            HandleIdentityPublicKeyFiles( monitor, identityPath, ids[0] );
            return new LocalKeys( _local, protector, ids, allowedOfflineDays );
        }

        void HandleIdentityPublicKeyFiles( IActivityMonitor monitor, NormalizedPath identityPath, LocalIdentityKey current )
        {
            try
            {
                var currentPath = $"{identityPath}/Identity.{current.Name}.public";
                string? foundCurrent = null;
                foreach( var f in Directory.EnumerateFiles( identityPath, RemoteKeys.PublicIdentityFilePattern ) )
                {
                    NormalizedPath fNormalized = f;
                    if( StringComparer.OrdinalIgnoreCase.Equals( fNormalized, currentPath ) )
                    {
                        foundCurrent = fNormalized;
                    }
                    else
                    {
                        LogAndCleanup( monitor, fNormalized, $"Obsolete Identity public key '{fNormalized}'." );
                    }
                }
                if( foundCurrent != null )
                {
                    if( !File.ReadAllBytes( foundCurrent ).AsSpan().SequenceEqual( current.PublicKeyRawData.Span ) )
                    {
                        monitor.Warn( $"Invalid file content '{foundCurrent}' (does not contain the public key). Rewriting it." );
                        current.WritePublicKeyFile( currentPath );
                    }
                }
                else
                {
                    current.WritePublicKeyFile( currentPath );
                }
            }
            catch( Exception ex )
            {
                monitor.Error( $"While handling '{RemoteKeys.PublicIdentityFilePattern}' in '{identityPath}'.", ex );
            }
        }

        static (string Name, string FilePath) SaveIdentityFileAndPassword( IActivityMonitor monitor,
                                                                           IDataProtector protector,
                                                                           DateTime now,
                                                                           NormalizedPath identityPath,
                                                                           X509Certificate2 currentIdentity )
        {
            var name = now.ToString( FileUtil.FileNameUniqueTimeUtcFormat );
            var fileName = name + ".pfx";
            monitor.Info( $"Creating a new identity key: '{fileName}' that will expire on {currentIdentity.NotAfter:yyyy-MM-dd}." );
            // Let any exception flow here. This is not recoverable.
            // The PFX password is the CLEAR random string; only the .pwd side file is protected.
            // Note the overload pairing: Protect(byte[]) here must be read back by Unprotect(byte[])
            // in TryLoadPassword. Using the string overload on one side only produces a payload that
            // a real IDataProtector cannot unprotect, which trashes every stored identity at startup.
            var pwd = Util.GetRandomBase64UrlString( 20 );
            var fullName = identityPath.AppendPart( fileName );
            File.WriteAllBytes( fullName, currentIdentity.Export( X509ContentType.Pfx, pwd ) );
            File.WriteAllBytes( fullName + PasswordExtension, protector.Protect( Encoding.UTF8.GetBytes( pwd ) ) );
            return (name, fullName);
        }

        int ReadAllowedOfflineDays( IActivityMonitor monitor )
        {
            var s = _local.Configuration.Configuration["AllowedOfflineDays"];
            if( s != null )
            {
                if( int.TryParse( s, out var allowedOfflineDays ) )
                {
                    if( allowedOfflineDays < ILocalKeys.MinAllowedOfflineDays )
                    {
                        monitor.Warn( $"Configuration '{_local.Configuration.Configuration.Path}:AllowedOfflineDays' is too small: using {nameof(ILocalKeys.MinAllowedOfflineDays)} = {ILocalKeys.MinAllowedOfflineDays}." );
                        allowedOfflineDays = ILocalKeys.MinAllowedOfflineDays;
                    }
                    else if( allowedOfflineDays > ILocalKeys.MaxAllowedOfflineDays )
                    {
                        monitor.Warn( $"Configuration '{_local.Configuration.Configuration.Path}:AllowedOfflineDays' is too big: using {nameof(ILocalKeys.MaxAllowedOfflineDays)} = {ILocalKeys.MaxAllowedOfflineDays}." );
                        allowedOfflineDays = ILocalKeys.MaxAllowedOfflineDays;
                    }
                    return allowedOfflineDays;
                }
                else
                {
                    monitor.Warn( $"Invalid configuration '{_local.Configuration.Configuration.Path}:AllowedOfflineDays' = '{s}': using {nameof( ILocalKeys.DefaultAllowedOfflineDays )} = {ILocalKeys.DefaultAllowedOfflineDays}." );
                }
            }
            return ILocalKeys.DefaultAllowedOfflineDays;
        }

        List<LocalIdentityKey> LoadIdentityKeys( IActivityMonitor monitor, IDataProtector protector, DateTime now, NormalizedPath folderPath )
        {
            var result = new List<LocalIdentityKey>();
            Directory.CreateDirectory( folderPath );
            foreach( var (name,timeName,pfxPath) in FilterFileNames( monitor, now, Directory.EnumerateFiles( folderPath, "*.pfx" ), null ) )
            {
                var pwd = TryLoadPassword( monitor, protector, pfxPath );
                if( pwd != null )
                {
                    X509Certificate2 c;
                    try
                    {
                        c = new X509Certificate2( File.ReadAllBytes( pfxPath ), pwd );
                        var privateKey = ValidateIdentityAndGetPrivateKey( monitor, now, pfxPath, c );
                        if( privateKey == null )
                        {
                            c.Dispose();
                        }
                        else
                        {
                            result.Add( new LocalIdentityKey( name, timeName, c, privateKey ) );
                        }
                    }
                    catch( Exception ex )
                    {
                        LogAndCleanup( monitor, pfxPath, $"Error while loading key '{pfxPath}'.", LogLevel.Error, ex );
                    }
                }
            }
            result.Sort( ( e1, e2 ) => StringComparer.Ordinal.Compare( e2.Name, e1.Name ) );
            return result;
        }

        string? TryLoadPassword( IActivityMonitor monitor, IDataProtector protector, in NormalizedPath pfxPath )
        {
            var pwdPath = pfxPath + PasswordExtension;
            if( !File.Exists( pwdPath ) )
            {
                LogAndCleanup( monitor, pfxPath, $"Missing password key file for '{pfxPath}'." );
                return null;
            }
            try
            {
                return Encoding.UTF8.GetString( protector.Unprotect( File.ReadAllBytes( pwdPath ) ) );
            }
            catch( Exception ex )
            {
                LogAndCleanup( monitor, pfxPath, $"Unable to read password key file for '{pfxPath}'.", LogLevel.Error, ex );
                return null;
            }
        }

        ECDsa? ValidateIdentityAndGetPrivateKey( IActivityMonitor monitor, DateTime now, in NormalizedPath filePath, X509Certificate2 c )
        {
            ECDsa? privateKey = null;
            bool success = true;
            // X509Certificate2.NotAfter/NotBefore are LOCAL time while now is UtcNow: comparing them
            // raw compares tick values and silently applies the machine's UTC offset to the decision,
            // up to ±14 h. East of UTC a key looks fresher than it is and rotation happens late; west
            // of UTC it looks expired and LogAndCleanup TRASHES it. This runs on every load, not only
            // on creation, so the conversion has to happen here and not just where the key is exposed.
            var notAfter = c.NotAfter.ToUniversalTime();
            var notBefore = c.NotBefore.ToUniversalTime();
            if( notAfter <= now.AddDays( 1 ) )
            {
                LogAndCleanup( monitor, filePath, $"Expired certificate '{filePath}' (NotAfter: {notAfter:u})." );
                success = false;
            }
            if( notBefore >= now )
            {
                LogAndCleanup( monitor,
                               filePath,
                               $"Certificate '{filePath}' is not yet valid (NotBefore: {notBefore:u}). This is not supported.",
                               tags: ActivityMonitor.Tags.ToBeInvestigated );
                success = false;
            }
            // Compare the DECODED common name, never the rendered Subject string.
            //
            // X500DistinguishedName.Name runs the value through a DN formatter, and whether that
            // formatter quotes depends on the characters in the name and on the platform: on Windows
            // CertNameToStr quotes for , + = " \n < > ; # and edge whitespace. A full name like
            // Test/$Party/#Dev contains a '#', so it renders quoted here and would render unquoted on
            // a name without one — an equality test against a hand-built "CN=\"…\"" literal therefore
            // passes or fails on the punctuation of the party name and on the host OS. A key that
            // fails it is not merely rejected, it is TRASHED, so getting this wrong destroys the
            // identity every remote has pinned.
            //
            // GetNameInfo decodes the attribute and hands back the value itself, with no formatter in
            // the way.
            var actualName = c.GetNameInfo( X509NameType.SimpleName, forIssuer: false );
            if( !string.Equals( actualName, _local.FullName, StringComparison.Ordinal ) )
            {
                LogAndCleanup( monitor,
                               filePath,
                               $"Invalid certificate common name (expected '{_local.FullName}', got '{actualName}') for '{filePath}'." );
                success = false;
            }
            // The identity issues the credentials other purposes need (LocalIdentityKey.CreateDerivedCertificate),
            // and CertificateRequest.Create refuses a non-CA signer outright — checked: it throws
            // ArgumentException rather than silently producing an unusable certificate. Deciding it
            // here turns that into one logged rotation at startup, with a new .public file that the
            // usual trust flow carries. Leaving it to the first issuance instead would throw on a
            // connection path, on every connection, with nothing that ever repairs itself.
            var constraints = c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if( constraints == null || !constraints.CertificateAuthority )
            {
                LogAndCleanup( monitor,
                               filePath,
                               $"Certificate '{filePath}' cannot issue: its BasicConstraints does not assert CA." );
                success = false;
            }
            if( !c.HasPrivateKey )
            {
                LogAndCleanup( monitor, filePath, $"Missing private key in '{filePath}'." );
            }
            else if( success )
            {
                privateKey = c.GetECDsaPrivateKey();
                if( privateKey == null )
                {
                    LogAndCleanup( monitor, filePath, $"Private key in '{filePath}' is not a ECDsa algorithm or its KeyUsages is invalid." );
                }
            }
            return privateKey;
        }

        protected override void DoTrash( IActivityMonitor monitor, in NormalizedPath path )
        {
            base.DoTrash( monitor, path );
            _store.TryTrash( monitor, path + PasswordExtension );
        }

        static X509Certificate2 CreateIdentityCertificate( string commonName, DateTime notAfter, DateTime now )
        {
            Throw.DebugAssert( notAfter > now );
            using( var ecdsa = ECDsa.Create() )
            {
                Throw.CheckState( "Unable to create ECDsa.", ecdsa != null );
                ecdsa.KeySize = 256;
                var request = new CertificateRequest( $"CN={commonName}",
                                                      ecdsa,
                                                      HashAlgorithmName.SHA256 );

                // This key has two jobs, and the second one is what keeps the first one contained.
                // DigitalSignature signs message transcripts. KeyCertSign lets it ISSUE the
                // purpose-specific credentials a transport needs — see
                // LocalIdentityKey.CreateDerivedCertificate — so a mutual TLS channel gets a
                // certificate with a key pair of its own instead of a copy of this one. The weaker
                // arrangement is a single end-entity key used directly for everything: it then has to
                // leave the package that owns it for every new purpose, and one exposure is total.
                request.CertificateExtensions.Add( new X509KeyUsageExtension( keyUsages: X509KeyUsageFlags.KeyCertSign
                                                                                         | X509KeyUsageFlags.DigitalSignature,
                                                                              critical: true ) );

                // CA:true, and pathLen 0 to say that it may issue leaves and nothing else: no
                // credential derived from this identity can itself become an issuer. Asserting CA
                // without the path length constraint would leave an unbounded chain hanging off a key
                // that lives on every node of a fleet.
                request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: true,
                                                                                      hasPathLengthConstraint: true,
                                                                                      pathLengthConstraint: 0,
                                                                                      critical: true ) );
                // This subject key identifier: let's use the standard SHA1 of the public key here.
                // RFC 5280 §4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
                request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, critical: false ) );

                // certificate expiry: Valid from yesterday to notAfter.
                var notBefore = now.AddDays( -1 );
                return request.CreateSelfSigned( notBefore, notAfter );
            }
        }
    }
}
