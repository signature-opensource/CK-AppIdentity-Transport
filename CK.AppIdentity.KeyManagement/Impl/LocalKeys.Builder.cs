using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CK.PerfectEvent;

namespace CK.AppIdentity.KeyManagement;


sealed partial class LocalKeys
{
    internal sealed class Builder
    {
        readonly ILocalParty _local;
        readonly IDataProtectionProvider _protectionProvider;
        readonly ICoreKeyStore _keyStore;
        readonly IFileStore _store;
        readonly PerfectEventSender<IdentityAlert>? _driverAlertRaised;

        public Builder( ILocalParty local, IDataProtectionProvider protectionProvider, ICoreKeyStore keyStore, PerfectEventSender<IdentityAlert>? driverAlertRaised = null )
        {
            _local = local;
            _protectionProvider = protectionProvider;
            _keyStore = keyStore;
            _driverAlertRaised = driverAlertRaised;
            _store = local.LocalFileStore;
        }

        /// <summary>
        /// Loads the identity, completing whatever a crash interrupted, and rotates if the current
        /// key is near its expiry.
        /// <para>
        /// The log is the truth. Its head <c>h</c> is the current key: <c>{h}</c> must open, keys
        /// below <c>h</c> are leftovers of a rotation that crashed before deleting them, keys beyond
        /// <c>h+1</c> are leftovers of one that crashed before its commit point (nothing commits to
        /// them), and <c>Current.cer</c> is public data re-minted whenever it does not match.
        /// </para>
        /// </summary>
        public LocalKeys Build( IActivityMonitor monitor )
        {
            var protector = _protectionProvider.CreateProtector( _local.FullName.Path );
            int allowedOfflineDays = ReadAllowedOfflineDays( monitor );
            int operationalKeyDays = ReadOperationalKeyDays( monitor );
            int maxSignatureDays = ReadMaxSignatureDays( monitor, allowedOfflineDays );
            var now = _local.ApplicationIdentityService.SystemClock.UtcNow;
            var keysPath = _store.FolderPath.AppendPart( "Keys" );
            var kelPath = keysPath.AppendPart( KelFolderName );
            _store.CreateDirectory( kelPath );
            TrashLegacyFiles( monitor, keysPath );

            var alerts = IdentityAlertBook.Load( monitor, _local, keysPath.AppendPart( "Alerts" ) );
            var log = LoadLog( monitor, kelPath );
            LocalIdentityKey current;
            if( log.Count == 0 )
            {
                (current, var inception) = Incept( monitor, keysPath, kelPath, allowedOfflineDays, now );
                log.Add( inception );
            }
            else
            {
                // A recovery that crashed between its two events: its head reveals the recovery key, which
                // is not a key of the store. The online key it committed to is, and finishes it.
                if( log[^1].IsRecovery ) CompleteRecovery( monitor, kelPath, log, now );
                current = LoadCurrent( monitor, keysPath, log, allowedOfflineDays, now, alerts );
            }
            var keys = new LocalKeys( _local, protector, _keyStore, keysPath, current, log.ToArray(), allowedOfflineDays, operationalKeyDays, maxSignatureDays, alerts, _driverAlertRaised );

            keys.RotateIfDue( monitor, now );
            var c = keys.CurrentIdentity;
            ExposeIdentity( monitor, _store, keysPath, keys.State.Head );
            monitor.Info( $"Local '{_local.FullName}' identity key is #{keys.Seq}, expiring on {c.NotAfter:yyyy-MM-dd}." );
            return keys;
        }

        (LocalIdentityKey, KeyEvent) Incept( IActivityMonitor monitor, NormalizedPath keysPath, NormalizedPath kelPath, int allowedOfflineDays, DateTime now )
        {
            // Keys without a log commit to nothing and are owned by no identity: a fresh start means
            // a fresh store.
            foreach( var n in _keyStore.GetKeyNames( monitor, _local ) )
            {
                monitor.Warn( $"Deleting key '{n}' of '{_local.FullName}': there is no key event log for it." );
                _keyStore.DeleteKey( monitor, _local, n );
            }
            monitor.Warn( $"No identity found for '{_local.FullName}': creating a new one. Every remote will have to approve it." );
            _keyStore.CreateKey( monitor, _local, KeyName( 0 ) );
            var nextSpki = _keyStore.CreateKey( monitor, _local, KeyName( 1 ) );
            var recoveryCommit = InceptRecovery( monitor );
            var key = _keyStore.OpenKey( monitor, _local, KeyName( 0 ) );
            Throw.CheckState( "A key just created cannot be opened.", key != null );
            try
            {
                var e = KeyEvent.Create( _local.FullName, 0, now, key, KeyEvent.ComputeCommit( nextSpki.Span ), null, recoveryCommit );
                _store.WriteAllBytes( kelPath.AppendPart( KeyName( 0 ) + EventExtension ), e.Encoded );
                var cert = CreateIdentityCertificate( key, _local.FullName, now.AddDays( 2 * allowedOfflineDays ), now );
                _store.WriteAllBytes( keysPath.AppendPart( CurrentCertificateFileName ), cert.Export( X509ContentType.Cert ) );
                return (NewIdentity( e, cert, key ), e);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        LocalIdentityKey LoadCurrent( IActivityMonitor monitor, NormalizedPath keysPath, List<KeyEvent> log, int allowedOfflineDays, DateTime now, IdentityAlertBook alerts )
        {
            var head = log[^1];
            if( head.IsAbandonment )
            {
                Throw.CKException( $"Local '{_local.FullName}' has been decommissioned (event #{head.Seq}): its identity has ended. " +
                                   $"Reset its 'Keys' folder and its key store to start a new identity, that every remote will have to approve." );
            }
            int h = head.Seq;
            var key = _keyStore.OpenKey( monitor, _local, KeyName( h ) );
            if( key == null )
            {
                // Never papered over by a new inception: a key store that cannot be read today (a
                // missing key ring) would otherwise silently become a new identity.
                Throw.CKException( $"The current identity key of '{_local.FullName}' (#{h}) cannot be opened. Fix the key store, or reset " +
                                   $"the party's 'Keys' folder and key store to start a new identity, that every remote will have to approve." );
            }
            try
            {
                Throw.CheckState( $"The key stored as #{h} for '{_local.FullName}' is not the one its event reveals.",
                                  key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual( head.Spki.Span ) );
                DeleteLeftoverKeys( monitor, h, RecoveryKeyName( log ) );
                // Says so loudly when the next key is missing; the party still works.
                using( OpenCommittedNextKey( monitor, _local, _keyStore, head, alerts ) ) { }

                var certPath = keysPath.AppendPart( CurrentCertificateFileName );
                var cert = TryLoadCertificate( monitor, certPath, head, now );
                if( cert == null )
                {
                    cert = CreateIdentityCertificate( key, _local.FullName, now.AddDays( 2 * allowedOfflineDays ), now );
                    _store.WriteAllBytes( certPath, cert.Export( X509ContentType.Cert ) );
                }
                else
                {
                    var withKey = cert.CopyWithPrivateKey( key );
                    cert.Dispose();
                    cert = withKey;
                }
                return NewIdentity( head, cert, key );
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        void DeleteLeftoverKeys( IActivityMonitor monitor, int h, string? currentRecoveryKey )
        {
            foreach( var n in _keyStore.GetKeyNames( monitor, _local ) )
            {
                if( n == currentRecoveryKey ) continue;
                if( !int.TryParse( n, NumberStyles.None, CultureInfo.InvariantCulture, out var seq ) || seq < h || seq > h + 1 )
                {
                    monitor.Info( $"Deleting leftover key '{n}' of '{_local.FullName}': the current key is #{h}." );
                    _keyStore.DeleteKey( monitor, _local, n );
                }
            }
        }

        /// <summary>
        /// Loads <c>Current.cer</c> and checks it is the identity certificate of the head's key: same
        /// public key, the party's name, the identity profile, currently valid. Null when it is not:
        /// the caller re-mints it, since the certificate is public data and the key is what matters.
        /// </summary>
        X509Certificate2? TryLoadCertificate( IActivityMonitor monitor, NormalizedPath certPath, KeyEvent head, DateTime now )
        {
            if( !File.Exists( certPath ) )
            {
                monitor.Info( $"Missing '{certPath}': minting it." );
                return null;
            }
            X509Certificate2? c = null;
            try
            {
                c = X509CertificateLoader.LoadCertificate( _store.ReadAllBytes( certPath ) );
                string? problem = null;
                // X509Certificate2.NotAfter/NotBefore are LOCAL time while now is UtcNow: comparing them
                // raw silently applies the machine's UTC offset to the decision, up to ±14 h.
                var notAfter = c.NotAfter.ToUniversalTime();
                var notBefore = c.NotBefore.ToUniversalTime();
                if( !c.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual( head.Spki.Span ) ) problem = "it is not the certificate of the current key";
                // Compare the DECODED common name, never the rendered Subject string: the DN formatter
                // quotes depending on the characters in the name and on the platform.
                else if( !string.Equals( c.GetNameInfo( X509NameType.SimpleName, forIssuer: false ), _local.FullName, StringComparison.Ordinal ) ) problem = "its common name is not the party's full name";
                else if( c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true, HasPathLengthConstraint: true, PathLengthConstraint: 0 } )
                {
                    // CertificateRequest.Create refuses a non-CA issuer outright: deciding it here
                    // keeps it off the connection path.
                    problem = "it cannot issue (BasicConstraints must assert CA with a path length of 0)";
                }
                else if( notBefore >= now ) problem = $"it is not yet valid (NotBefore: {notBefore:u})";
                else if( notAfter <= now ) problem = $"it has expired (NotAfter: {notAfter:u})";
                if( problem == null ) return c;
                monitor.Warn( $"Re-minting '{certPath}' for the same key: {problem}." );
            }
            catch( Exception ex )
            {
                monitor.Warn( $"Unable to read '{certPath}': re-minting it for the same key.", ex );
            }
            c?.Dispose();
            return null;
        }

        List<KeyEvent> LoadLog( IActivityMonitor monitor, NormalizedPath kelPath )
        {
            var events = new SortedList<int, KeyEvent>();
            foreach( var f in Directory.EnumerateFiles( kelPath, "*" + EventExtension ) )
            {
                var name = Path.GetFileNameWithoutExtension( f );
                if( !int.TryParse( name, NumberStyles.None, CultureInfo.InvariantCulture, out var seq ) )
                {
                    monitor.Warn( $"Ignoring '{f}': not a key event file name." );
                    continue;
                }
                KeyEvent e;
                try
                {
                    e = KeyEvent.Read( _store.ReadAllBytes( f ) );
                }
                catch( Exception ex )
                {
                    Throw.CKException( $"Unreadable key event '{f}' in the log of '{_local.FullName}'.", ex );
                    throw;
                }
                Throw.CheckState( $"Key event '{f}' holds event #{e.Seq}.", e.Seq == seq );
                events.Add( seq, e );
            }
            var log = events.Values.ToList();
            // An own log that does not verify is not repaired: it was written atomically by this very
            // code, so a broken one means tampering or a damaged disk, and starting a new identity
            // silently would hide either.
            if( log.Count > 0 && !KeyEventChain.IsValidLog( _local.FullName, log ) )
            {
                Throw.CKException( $"The key event log of '{_local.FullName}' in '{kelPath}' does not verify." );
            }
            return log;
        }

        /// <summary>
        /// No migration (DESIGN-key-pre-rotation Q1): the identity files of the previous layout are
        /// sent to the '$TrashBin'.
        /// </summary>
        void TrashLegacyFiles( IActivityMonitor monitor, NormalizedPath keysPath )
        {
            foreach( var f in Directory.EnumerateFiles( keysPath, "*.pfx" ).Concat( Directory.EnumerateFiles( keysPath, "*" + PasswordExtension ) ).ToArray() )
            {
                monitor.Info( $"Trashing '{f}': identity keys are now held by the {nameof( ICoreKeyStore )}." );
                _store.TryTrash( monitor, f );
            }
        }

        /// <summary>
        /// The commitment of a new identity to its recovery key.
        /// <para>
        /// With "RecoveryPublicKey" configured (the base64 SubjectPublicKeyInfo of a P-256 key generated
        /// and kept offline), the identity commits to it and nothing is stored here: this is what makes a
        /// recovery possible after the host itself was compromised. Without it, a recovery key is
        /// created in the key store, which only helps when the next key leaked on its own - and that is
        /// said, once, as a warning.
        /// </para>
        /// </summary>
        byte[] InceptRecovery( IActivityMonitor monitor )
        {
            var configured = _local.Configuration.Configuration["RecoveryPublicKey"];
            if( configured != null )
            {
                byte[] spki;
                try
                {
                    spki = Convert.FromBase64String( configured );
                    using var check = ECDsa.Create();
                    check.ImportSubjectPublicKeyInfo( spki, out int read );
                    Throw.CheckData( read == spki.Length && check.KeySize == 256 );
                }
                catch( Exception ex )
                {
                    Throw.CKException( $"Configuration '{_local.Configuration.Configuration.Path}:RecoveryPublicKey' must be the base64 SubjectPublicKeyInfo of a P-256 key.", ex );
                    throw;
                }
                monitor.Info( $"The identity of '{_local.FullName}' commits to the configured offline recovery key." );
                return KeyEvent.ComputeCommit( spki );
            }
            monitor.Warn( $"No 'RecoveryPublicKey' configured for '{_local.FullName}': its recovery key is kept in the key store. " +
                          $"It can take the identity back after a leak of the next key alone, not after a compromise of this host." );
            return KeyEvent.ComputeCommit( _keyStore.CreateKey( monitor, _local, RecoveryKeyName( 0 ) ).Span );
        }

        /// <summary>
        /// Writes the ordinary event that follows a recovery event, which a crash interrupted: it reveals
        /// the online key the recovery committed to.
        /// </summary>
        void CompleteRecovery( IActivityMonitor monitor, NormalizedPath kelPath, List<KeyEvent> log, DateTime now )
        {
            var r = log[^1];
            using var next = _keyStore.OpenKey( monitor, _local, KeyName( r.Seq + 1 ) );
            if( next == null || !r.CommitsTo( next.ExportSubjectPublicKeyInfo() ) )
            {
                Throw.CKException( $"The recovery #{r.Seq} of '{_local.FullName}' was interrupted and the key it committed to is missing: run the recovery again." );
            }
            _keyStore.DeleteKey( monitor, _local, KeyName( r.Seq + 2 ) );
            var after = _keyStore.CreateKey( monitor, _local, KeyName( r.Seq + 2 ) );
            var e = KeyEvent.Create( _local.FullName, r.Seq + 1, now, next, KeyEvent.ComputeCommit( after.Span ), r );
            _store.WriteAllBytes( kelPath.AppendPart( KeyName( e.Seq ) + EventExtension ), e.Encoded );
            log.Add( e );
            monitor.Warn( $"Completed the interrupted recovery of '{_local.FullName}': identity key is now #{e.Seq}." );
        }

        int ReadOperationalKeyDays( IActivityMonitor monitor )
        {
            var s = _local.Configuration.Configuration["OperationalKeyDays"];
            if( s == null ) return ILocalKeys.DefaultOperationalKeyDays;
            if( !int.TryParse( s, out var days ) )
            {
                monitor.Warn( $"Invalid configuration '{_local.Configuration.Configuration.Path}:OperationalKeyDays' = '{s}': using {nameof( ILocalKeys.DefaultOperationalKeyDays )} = {ILocalKeys.DefaultOperationalKeyDays}." );
                return ILocalKeys.DefaultOperationalKeyDays;
            }
            if( days < 1 || days > ILocalKeys.MaxOperationalKeyDays )
            {
                var clamped = Math.Clamp( days, 1, ILocalKeys.MaxOperationalKeyDays );
                monitor.Warn( $"Configuration '{_local.Configuration.Configuration.Path}:OperationalKeyDays' = {days} is out of 1..{ILocalKeys.MaxOperationalKeyDays}: using {clamped}." );
                return clamped;
            }
            return days;
        }

        int ReadMaxSignatureDays( IActivityMonitor monitor, int allowedOfflineDays )
        {
            var path = _local.Configuration.Configuration.Path;
            var s = _local.Configuration.Configuration["MaxSignatureDays"];
            int days = ILocalKeys.DefaultMaxSignatureDays;
            if( s != null && !int.TryParse( s, out days ) )
            {
                monitor.Warn( $"Invalid configuration '{path}:MaxSignatureDays' = '{s}': using {nameof( ILocalKeys.DefaultMaxSignatureDays )} = {ILocalKeys.DefaultMaxSignatureDays}." );
                days = ILocalKeys.DefaultMaxSignatureDays;
            }
            // Bounded by AllowedOfflineDays: a credential issued just before a rotation must end within
            // its issuer's life, and a verifier accepts no longer than its own AllowedOfflineDays.
            if( days < 1 || days > allowedOfflineDays )
            {
                var clamped = Math.Clamp( days, 1, allowedOfflineDays );
                monitor.Warn( $"Configuration '{path}:MaxSignatureDays' = {days} is out of 1..AllowedOfflineDays ({allowedOfflineDays}): using {clamped}." );
                days = clamped;
            }
            return days;
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
    }
}
