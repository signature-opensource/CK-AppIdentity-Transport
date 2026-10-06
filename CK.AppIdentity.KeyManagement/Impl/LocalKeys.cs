using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using CK.PerfectEvent;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The local party's identity: one identity key, and the key event log that says which key that is
/// and which one comes next.
/// <para>
/// On disk, under <c>-Local/Keys</c>: the log (<c>Kel/{Seq}.event</c>) and the current identity
/// certificate (<c>Current.cer</c>, public). The private keys are in the <see cref="ICoreKeyStore"/>,
/// named by their sequence number: the current one is the head of the log, the next one is head + 1.
/// The log is the single source of truth, and nothing is ever renamed.
/// </para>
/// </summary>
sealed partial class LocalKeys : ILocalKeys
{
    const string PasswordExtension = ".pwd";
    const string KelFolderName = "Kel";
    const string EventExtension = ".event";
    const string CurrentCertificateFileName = "Current.cer";

    readonly ILocalParty _local;
    readonly IDataProtector _protector;
    readonly ICoreKeyStore _keyStore;
    readonly NormalizedPath _keysPath;
    readonly int _allowedOfflineDays;
    // Serializes Rotate and Decommission. Readers never take it: they read the arrays below, which
    // are replaced as a whole.
    readonly object _rotationLock;
    // Replaced as a whole on rotation: TransportFeature detects a rotation by reference inequality,
    // so this must be an array (not an ImmutableArray, whose equality is by content).
    LocalIdentityKey[] _identities;
    KeyEvent[] _log;

    readonly IdentityAlertBook _alerts;
    readonly PerfectEventSender<IdentityAlert> _alertRaised;
    // The driver's event, raised after ours: one place for an application to subscribe for every local party.
    readonly PerfectEventSender<IdentityAlert>? _driverAlertRaised;

    LocalKeys( ILocalParty local,
               IDataProtector protector,
               ICoreKeyStore keyStore,
               NormalizedPath keysPath,
               LocalIdentityKey current,
               KeyEvent[] log,
               int allowedOfflineDays,
               IdentityAlertBook alerts,
               PerfectEventSender<IdentityAlert>? driverAlertRaised )
    {
        _local = local;
        _protector = protector;
        _keyStore = keyStore;
        _keysPath = keysPath;
        _identities = [current];
        _log = log;
        _allowedOfflineDays = allowedOfflineDays;
        _rotationLock = new object();
        _alerts = alerts;
        _alertRaised = new PerfectEventSender<IdentityAlert>();
        _driverAlertRaised = driverAlertRaised;
        local.ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
    }

    public IReadOnlyList<IdentityAlert> Alerts => _alerts.Alerts;

    public PerfectEvent<IdentityAlert> AlertRaised => _alertRaised.PerfectEvent;

    public bool Acknowledge( IActivityMonitor monitor, IdentityAlert alert ) => _alerts.Acknowledge( monitor, alert );

    internal IdentityAlertBook AlertBook => _alerts;

    public bool ReportPinStatement( IActivityLineEmitter logger, string reporter, int seq, ReadOnlySpan<byte> eventDigest )
    {
        Throw.CheckNotNullOrEmptyArgument( reporter );
        Throw.CheckArgument( seq >= 0 );
        Throw.CheckArgument( eventDigest.Length == KeyEvent.HashSize );
        var log = _log;
        var head = log[^1];
        if( seq > head.Seq )
        {
            _alerts.Raise( logger, IdentityAlertKind.IdentityTakenOver, _local.FullName, true, reporter, seq,
                           head.GetDigest( _local.FullName ).Span, eventDigest );
            return true;
        }
        // The log is complete from the inception: event 'seq' is at index 'seq'.
        var own = log[seq].GetDigest( _local.FullName ).Span;
        if( CryptographicOperations.FixedTimeEquals( own, eventDigest ) ) return false;
        _alerts.Raise( logger, IdentityAlertKind.IdentityForked, _local.FullName, true, reporter, seq, own, eventDigest );
        return true;
    }

    async Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, CancellationToken cancel )
    {
        foreach( var a in _alerts.Flush( monitor ) )
        {
            await _alertRaised.SafeRaiseAsync( monitor, a, cancel ).ConfigureAwait( false );
            if( _driverAlertRaised != null ) await _driverAlertRaised.SafeRaiseAsync( monitor, a, cancel ).ConfigureAwait( false );
        }
    }

    public ILocalParty Party => _local;

    public int AllowedOfflineDays => _allowedOfflineDays;

    public IDataProtector Protector => _protector;

    public LocalIdentityKey CurrentIdentity => _identities[0];

    public IReadOnlyList<LocalIdentityKey> Identities => _identities;

    public int Seq => _log[^1].Seq;

    public IReadOnlyList<KeyEvent> EventTail
    {
        get
        {
            var log = _log;
            return log.Length <= KeyEventChain.MaxEventTail ? log : log[^KeyEventChain.MaxEventTail..];
        }
    }

    public bool IsDecommissioned => _log[^1].IsAbandonment;

    static string KeyName( int seq ) => seq.ToString( CultureInfo.InvariantCulture );

    NormalizedPath KelPath => _keysPath.AppendPart( KelFolderName );

    NormalizedPath CurrentCertificatePath => _keysPath.AppendPart( CurrentCertificateFileName );

    public bool Rotate( IActivityMonitor monitor )
    {
        lock( _rotationLock )
        {
            var head = _log[^1];
            if( head.IsAbandonment )
            {
                monitor.Error( $"Local '{_local.FullName}' is decommissioned: it cannot rotate." );
                return false;
            }
            int s = head.Seq;
            var next = OpenCommittedNextKey( monitor, _local, _keyStore, head, _alerts );
            if( next == null ) return false;
            bool nextOwned = true;
            try
            {
                // A key at s+2 can only be the orphan of a rotation that crashed before its commit
                // point: nothing commits to it, so it is replaced.
                _keyStore.DeleteKey( monitor, _local, KeyName( s + 2 ) );
                var afterNext = _keyStore.CreateKey( monitor, _local, KeyName( s + 2 ) );
                var now = _local.ApplicationIdentityService.SystemClock.UtcNow;
                var e = KeyEvent.Create( _local.FullName, s + 1, now, next, KeyEvent.ComputeCommit( afterNext.Span ), head );

                // The commit point: from here, the log says s+1 is current. A crash after this line
                // leaves a state the next start completes (see Builder).
                WriteEvent( e );
                _log = [.. _log, e];

                var identity = CreateIdentity( monitor, next, e, now );
                nextOwned = false;
                // The replaced key is NOT disposed: a negotiation may be signing with it right now.
                // One finalizable key per rotation, rotations being AllowedOfflineDays apart.
                _identities = [identity];
                _keyStore.DeleteKey( monitor, _local, KeyName( s ) );
                HandleIdentityPublicKeyFiles( monitor, _local.LocalFileStore, _keysPath, identity );
                monitor.Info( $"Local '{_local.FullName}' rotated its identity key to #{e.Seq}. Current expires on {identity.NotAfter:yyyy-MM-dd}." );
                return true;
            }
            catch( Exception ex )
            {
                monitor.Error( $"While rotating the identity key of '{_local.FullName}'. If the event was written, the next start completes the rotation.", ex );
                return false;
            }
            finally
            {
                if( nextOwned ) next.Dispose();
            }
        }
    }

    public bool Decommission( IActivityMonitor monitor )
    {
        lock( _rotationLock )
        {
            var head = _log[^1];
            if( head.IsAbandonment ) return false;
            int s = head.Seq;
            // Only the committed next key can end the identity: a thief holding the current key
            // cannot use this to knock the party offline.
            using var next = OpenCommittedNextKey( monitor, _local, _keyStore, head, _alerts );
            if( next == null ) return false;
            try
            {
                var now = _local.ApplicationIdentityService.SystemClock.UtcNow;
                var e = KeyEvent.Create( _local.FullName, s + 1, now, next, ReadOnlySpan<byte>.Empty, head );
                WriteEvent( e );
                _log = [.. _log, e];
                foreach( var n in _keyStore.GetKeyNames( monitor, _local ) )
                {
                    _keyStore.DeleteKey( monitor, _local, n );
                }
                monitor.Warn( $"Local '{_local.FullName}' is decommissioned: its identity has ended. " +
                              $"It will refuse to start until its key store is reset, which starts a new identity." );
                return true;
            }
            catch( Exception ex )
            {
                monitor.Error( $"While decommissioning '{_local.FullName}'.", ex );
                return false;
            }
        }
    }

    /// <summary>
    /// Re-mints the current key's certificate with a fresh validity: what keeps a party working when
    /// its scheduled rotation cannot happen. The key does not change, so no remote notices.
    /// </summary>
    internal void RenewCertificate( IActivityMonitor monitor, DateTime now )
    {
        lock( _rotationLock )
        {
            var head = _log[^1];
            var key = _keyStore.OpenKey( monitor, _local, KeyName( head.Seq ) );
            if( key == null )
            {
                monitor.Error( $"Unable to renew the certificate of '{_local.FullName}': its current key cannot be opened." );
                return;
            }
            try
            {
                _identities = [CreateIdentity( monitor, key, head, now )];
                monitor.Warn( $"Identity certificate of '{_local.FullName}' renewed for the same key #{head.Seq}, until {CurrentIdentity.NotAfter:yyyy-MM-dd}." );
            }
            catch( Exception ex )
            {
                key.Dispose();
                monitor.Error( $"While renewing the certificate of '{_local.FullName}'.", ex );
            }
        }
    }

    /// <summary>
    /// Opens the next key and checks it is the one <paramref name="head"/> committed to. When it is not
    /// usable, says why and raises <see cref="IdentityAlertKind.NextKeyLost"/>.
    /// </summary>
    static ECDsa? OpenCommittedNextKey( IActivityMonitor monitor, ILocalParty local, ICoreKeyStore keyStore, KeyEvent head, IdentityAlertBook alerts )
    {
        var next = keyStore.OpenKey( monitor, local, KeyName( head.Seq + 1 ) );
        if( next == null )
        {
            monitor.Error( ActivityMonitor.Tags.ToBeInvestigated,
                           $"The next identity key of '{local.FullName}' (#{head.Seq + 1}) is missing: this party can neither rotate nor be revoked. " +
                           $"The current key keeps working. The only recovery is a new identity that every remote re-approves." );
            alerts.Raise( monitor, IdentityAlertKind.NextKeyLost, local.FullName, true, null, head.Seq + 1, head.NextCommit.Span, default );
            return null;
        }
        var spki = next.ExportSubjectPublicKeyInfo();
        if( !head.CommitsTo( spki ) )
        {
            next.Dispose();
            monitor.Error( ActivityMonitor.Tags.ToBeInvestigated,
                           $"The key stored as #{head.Seq + 1} for '{local.FullName}' is not the one event #{head.Seq} committed to." );
            alerts.Raise( monitor, IdentityAlertKind.NextKeyLost, local.FullName, true, null, head.Seq + 1, head.NextCommit.Span, KeyEvent.ComputeCommit( spki ) );
            return null;
        }
        return next;
    }

    void WriteEvent( KeyEvent e )
    {
        _local.LocalFileStore.CreateDirectory( KelPath );
        // Atomic: the log is never left with a truncated event.
        _local.LocalFileStore.WriteAllBytes( KelPath.AppendPart( KeyName( e.Seq ) + EventExtension ), e.Encoded );
    }

    /// <summary>
    /// Mints the identity certificate of <paramref name="key"/> (revealed by <paramref name="e"/>),
    /// stores it as <c>Current.cer</c> and returns the identity, which takes ownership of the key.
    /// </summary>
    LocalIdentityKey CreateIdentity( IActivityMonitor monitor, ECDsa key, KeyEvent e, DateTime now )
    {
        var cert = CreateIdentityCertificate( key, _local.FullName, now.AddDays( 2 * _allowedOfflineDays ), now );
        _local.LocalFileStore.WriteAllBytes( CurrentCertificatePath, cert.Export( X509ContentType.Cert ) );
        return NewIdentity( e, cert, key );
    }

    static LocalIdentityKey NewIdentity( KeyEvent e, X509Certificate2 certificateWithKey, ECDsa key )
        => new LocalIdentityKey( e.TimeName.ToString( FileUtil.FileNameUniqueTimeUtcFormat ), e.TimeName, certificateWithKey, key );

    /// <summary>
    /// Creates the self-signed identity certificate of a key. The certificate is public data and is
    /// re-minted whenever it is missing, invalid or near its expiry while the key stays the same.
    /// </summary>
    static X509Certificate2 CreateIdentityCertificate( ECDsa key, string commonName, DateTime notAfter, DateTime now )
    {
        Throw.DebugAssert( notAfter > now );
        var request = new CertificateRequest( $"CN={commonName}", key, HashAlgorithmName.SHA256 );

        // This key has two jobs, and the second one is what keeps the first one contained.
        // DigitalSignature signs message transcripts. KeyCertSign lets it ISSUE the purpose-specific
        // credentials a transport needs — see LocalIdentityKey.CreateDerivedCertificate — so a mutual
        // TLS channel gets a certificate with a key pair of its own instead of a copy of this one.
        request.CertificateExtensions.Add( new X509KeyUsageExtension( keyUsages: X509KeyUsageFlags.KeyCertSign
                                                                                 | X509KeyUsageFlags.DigitalSignature,
                                                                      critical: true ) );

        // CA:true, and pathLen 0 to say that it may issue leaves and nothing else: no credential
        // derived from this identity can itself become an issuer.
        request.CertificateExtensions.Add( new X509BasicConstraintsExtension( certificateAuthority: true,
                                                                              hasPathLengthConstraint: true,
                                                                              pathLengthConstraint: 0,
                                                                              critical: true ) );
        // RFC 5280 §4.2.1.2: "Conforming CAs MUST mark this extension as non-critical."
        request.CertificateExtensions.Add( new X509SubjectKeyIdentifierExtension( request.PublicKey, critical: false ) );

        // Valid from yesterday to notAfter.
        return request.CreateSelfSigned( now.AddDays( -1 ), notAfter );
    }

    /// <summary>
    /// Exposes the current public key as <c>Identity.{Name}.public</c> (the bare SPKI) for an operator
    /// to hand to a remote, and removes any other one.
    /// </summary>
    static void HandleIdentityPublicKeyFiles( IActivityMonitor monitor, IFileStore store, NormalizedPath keysPath, LocalIdentityKey current )
    {
        try
        {
            var currentPath = keysPath.AppendPart( $"Identity.{current.Name}.public" );
            foreach( var f in Directory.EnumerateFiles( keysPath, RemoteKeys.PublicIdentityFilePattern ) )
            {
                NormalizedPath p = f;
                if( !StringComparer.OrdinalIgnoreCase.Equals( p, currentPath ) )
                {
                    monitor.Info( $"Removing obsolete identity public key '{p}'." );
                    store.TryTrash( monitor, p );
                }
            }
            if( !File.Exists( currentPath )
                || !store.ReadAllBytes( currentPath ).AsSpan().SequenceEqual( current.PublicKeyRawData.Span ) )
            {
                store.WriteAllBytes( currentPath, current.PublicKeyRawData );
            }
        }
        catch( Exception ex )
        {
            monitor.Error( $"While handling '{RemoteKeys.PublicIdentityFilePattern}' in '{keysPath}'.", ex );
        }
    }

    /// <summary>
    /// Disposes the current identity key of this local party.
    /// <para>
    /// Known and accepted: a negotiation still in flight can be inside
    /// <see cref="LocalIdentityKey.TrySignHash"/> on it when this runs, and will then throw
    /// <see cref="ObjectDisposedException"/> into its back task, where it is caught and logged. This
    /// is reached only when the whole service is shutting down or the local party is being destroyed,
    /// so the connection that fails was about to be torn down anyway. Making it airtight means
    /// reference-counting every signing operation — real complexity, paid on every handshake, to
    /// avoid a logged exception on a path that is already ending. Not disposing at all is worse: this
    /// also runs on party destruction in a long-lived process, and those keys must go.
    /// </para>
    /// </summary>
    internal void OnTearDown( IActivityMonitor monitor )
    {
        _local.ApplicationIdentityService.Heartbeat.Async -= OnHeartbeatAsync;
        // Repetitions are saved from the heartbeat: the last ones must not be lost. Pending events
        // are dropped, but the alerts themselves are persisted and logged again at the next start.
        _alerts.Flush( monitor );
        foreach( var key in _identities )
        {
            key.OnTeardown();
        }
    }
}
