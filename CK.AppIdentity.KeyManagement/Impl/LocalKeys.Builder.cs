using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace CK.AppIdentity.KeyManagement
{

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

                var systemClock = _local.ApplicationIdentityService.SystemClock;
                var now = systemClock.UtcNow;
                var today = now.Date;
                var identityPath = _store.FolderPath.AppendPart( "Keys" );
                // File name matters:
                //   - The file name is in FileUtil.FileNameUniqueTimeUtcFormat format.
                //   - The date time parsed from the name is grater than now: This is our certificate name.
                //   - The certificates are sorted in reverse order of their certificate name.
                //   => The first one is the one to use, the current one, because it is the most recent one.
                List<LocalIdentityKey> identities = LoadIdentityKeys( monitor, protector, now, identityPath );
                // The certificate to consider is the last one of the list.
                // If it cannot guaranty the "AllowedOfflineDays", we must issue a new identity valid
                // from now up to twice the AllowedOfflineDays: we (or a remote) can safely be offline for this time span.
                if( identities.Count == 0 || identities[0].NotAfter < today.AddDays( allowedOfflineDays + 1 ) )
                {
                    var newOne = CreateIdentityCertificate( _local.FullName, today.AddDays( 2 * allowedOfflineDays ), now );
                    if( identities.Count == 0 ) monitor.Warn( $"No identity keys found in '{identityPath}'." );
                    else monitor.Info( $"Most recent identity key ({identities[0].Name}.pfx) expires on {newOne.NotAfter:yyyy-MM-dd}. " +
                                       $"It is not enough to guaranty AllowedOfflineDays = {allowedOfflineDays}." );

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
                // We load the nonce cache.
                var nonceCache = LocalNonceCache.Create( monitor, _store.FolderPath.AppendPart( "Nonce.cache" ) );
                return new LocalKeys( _local, protector, ids, nonceCache );
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
                            current.WriteFile( currentPath );
                        }
                    }
                    else
                    {
                        current.WriteFile( currentPath );
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
                var pwd = protector.Protect( Util.GetRandomBase64UrlString( 20 ) );
                var fullName = identityPath.AppendPart( fileName );
                File.WriteAllBytes( fullName, currentIdentity.Export( X509ContentType.Pfx, pwd ) );
                File.WriteAllText( fullName + PasswordExtension, pwd );
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
                if( c.NotAfter <= now.AddDays( 1 ) )
                {
                    LogAndCleanup( monitor, filePath, $"Expired certificate '{filePath}'." );
                    success = false;
                }
                if( c.NotBefore >= now )
                {
                    LogAndCleanup( monitor, filePath, $"Certificate '{filePath}' is not yet valid (NotBefore: {c.NotBefore}). This is not supported.", tags: ActivityMonitor.Tags.ToBeInvestigated );
                    success = false;
                }
                var expectedSubject = $"CN=\"{_local.FullName}\"";
                if( c.Subject != expectedSubject )
                {
                    LogAndCleanup( monitor, filePath, $"Invalid certificate subject (expected '{expectedSubject}', got '{c.Subject}') for '{filePath}'." );
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
                using( var ecdsa = ECDsa.Create( "ECDsa" ) )
                {
                    Throw.CheckState( "Unable to create ECDsa.", ecdsa != null );
                    ecdsa.KeySize = 256;
                    var request = new CertificateRequest( $"CN={commonName}",
                                                          ecdsa,
                                                          HashAlgorithmName.SHA256 );

                    // key usage: Digital Signature and Certificate signing.
                    request.CertificateExtensions.Add( new X509KeyUsageExtension( keyUsages: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                                                                                  critical: true ) );

                    // Sets basic certificate constraints: this certificate is not intended
                    // be used to sign other CA certificates but is a CA.
                    request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: true,
                                                                                          hasPathLengthConstraint: true,
                                                                                          pathLengthConstraint: 0,
                                                                                          critical: true ) );
                    // This subject key identifier: let's use the standard SHA1 of the public key here.
                    request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, critical: true ) );

                    // certificate expiry: Valid from yesterday to notAfter.
                    var notBefore = now.AddDays( -1 );
                    return request.CreateSelfSigned( notBefore, notAfter );
                }
            }
        }
    }
}
