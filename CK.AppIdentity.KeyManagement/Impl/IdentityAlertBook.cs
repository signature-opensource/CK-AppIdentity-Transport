using CK.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The <see cref="IdentityAlert"/> of one local party: recorded, deduplicated, persisted until
/// acknowledged (<c>-Local/Keys/Alerts/{Id}.alert</c>), logged at once, and handed out for the event
/// to be raised from the next heartbeat.
/// <para>
/// Alerts are raised from back tasks that have no <see cref="IActivityMonitor"/>: everything here
/// accepts an <see cref="IActivityLineEmitter"/>, and the event, which needs a monitor, is deferred.
/// </para>
/// </summary>
sealed class IdentityAlertBook
{
    const string Extension = ".alert";
    static readonly CKTrait _tags = IdentityAlert.LogTag.Union( ActivityMonitor.Tags.ToBeInvestigated );

    readonly ILocalParty _local;
    readonly NormalizedPath _folder;
    readonly object _lock;
    readonly Dictionary<string, IdentityAlert> _alerts;
    readonly HashSet<string> _dirty;
    readonly List<IdentityAlert> _pending;

    sealed record AlertFile( IdentityAlertKind Kind,
                             string Subject,
                             bool IsAboutSelf,
                             string[] ReportedBy,
                             int Seq,
                             byte[] ExpectedDigest,
                             byte[] ObservedDigest,
                             DateTime FirstSeen,
                             DateTime LastSeen,
                             int Count );

    IdentityAlertBook( ILocalParty local, NormalizedPath folder, Dictionary<string, IdentityAlert> alerts )
    {
        _local = local;
        _folder = folder;
        _alerts = alerts;
        _lock = new object();
        _dirty = new HashSet<string>();
        _pending = new List<IdentityAlert>();
    }

    /// <summary>
    /// Loads the unacknowledged alerts and logs each one again: they stay loud until someone acknowledges them.
    /// </summary>
    public static IdentityAlertBook Load( IActivityMonitor monitor, ILocalParty local, NormalizedPath folder )
    {
        var alerts = new Dictionary<string, IdentityAlert>();
        if( Directory.Exists( folder ) )
        {
            foreach( var f in Directory.EnumerateFiles( folder, "*" + Extension ) )
            {
                var id = Path.GetFileNameWithoutExtension( f );
                try
                {
                    var d = JsonSerializer.Deserialize<AlertFile>( local.LocalFileStore.ReadAllBytes( f ) );
                    Throw.CheckData( d != null && d.Subject != null );
                    var a = new IdentityAlert( id, d.Kind, d.Subject, d.IsAboutSelf, d.ReportedBy ?? [], d.Seq,
                                               d.ExpectedDigest ?? [], d.ObservedDigest ?? [], d.FirstSeen, d.LastSeen, d.Count );
                    Throw.CheckData( "The file name is the identifier of its content.", ComputeId( a.Kind, a.Subject, a.Seq, a.ObservedDigest.Span ) == id );
                    alerts.Add( id, a );
                    monitor.Log( GetLevel( a.Kind ), _tags, $"Unacknowledged identity alert: {a}. {GetAdvice( a.Kind, a.Subject )}" );
                }
                catch( Exception ex )
                {
                    // Left in place: an alert file nobody can read is still something an operator should see.
                    monitor.Error( _tags, $"Unreadable identity alert file '{f}'. It is left in place.", ex );
                }
            }
        }
        return new IdentityAlertBook( local, folder, alerts );
    }

    /// <summary>
    /// Gets the unacknowledged alerts.
    /// </summary>
    public IReadOnlyList<IdentityAlert> Alerts
    {
        get
        {
            lock( _lock ) return _alerts.Values.OrderBy( a => a.FirstSeen ).ToArray();
        }
    }

    /// <summary>
    /// Records an alert, or a repetition of one.
    /// </summary>
    /// <returns>The alert, as it now stands.</returns>
    public IdentityAlert Raise( IActivityLineEmitter logger,
                                IdentityAlertKind kind,
                                string subject,
                                bool isAboutSelf,
                                string? reportedBy,
                                int seq,
                                ReadOnlySpan<byte> expectedDigest,
                                ReadOnlySpan<byte> observedDigest )
    {
        var id = ComputeId( kind, subject, seq, observedDigest );
        var now = _local.ApplicationIdentityService.SystemClock.UtcNow;
        lock( _lock )
        {
            IdentityAlert a;
            bool notify;
            if( _alerts.TryGetValue( id, out var existing ) )
            {
                bool newReporter = reportedBy != null && !existing.ReportedBy.Contains( reportedBy );
                a = new IdentityAlert( id, kind, subject, isAboutSelf,
                                       newReporter ? [.. existing.ReportedBy, reportedBy!] : existing.ReportedBy,
                                       seq, existing.ExpectedDigest, existing.ObservedDigest,
                                       existing.FirstSeen, now, existing.Count + 1 );
                // More remotes saying the same thing is stronger evidence; the same remote repeating
                // itself is not, and must not page anybody again.
                notify = newReporter;
            }
            else
            {
                a = new IdentityAlert( id, kind, subject, isAboutSelf,
                                       reportedBy != null ? [reportedBy] : [],
                                       seq, expectedDigest.ToArray(), observedDigest.ToArray(), now, now, 1 );
                notify = true;
            }
            _alerts[id] = a;
            if( notify )
            {
                Save( logger, a );
                _pending.Add( a );
                logger.Log( GetLevel( kind ), _tags, $"Identity alert: {a}. {GetAdvice( kind, subject )}" );
            }
            else
            {
                // Saved from the heartbeat: a repetition is not worth a write each time.
                _dirty.Add( id );
                logger.Log( LogLevel.Info, _tags, $"Identity alert repeated: {a}." );
            }
            return a;
        }
    }

    /// <summary>
    /// Acknowledges an alert: it is removed, and its file goes to the '$TrashBin'.
    /// </summary>
    /// <returns>True if the alert was pending.</returns>
    public bool Acknowledge( IActivityMonitor monitor, IdentityAlert alert )
    {
        Throw.CheckNotNullArgument( alert );
        lock( _lock )
        {
            if( !_alerts.Remove( alert.Id ) ) return false;
            _dirty.Remove( alert.Id );
            _pending.RemoveAll( p => p.Id == alert.Id );
            _local.LocalFileStore.TryTrash( monitor, GetPath( alert.Id ) );
        }
        monitor.Info( IdentityAlert.LogTag, $"Identity alert acknowledged: {alert}." );
        return true;
    }

    /// <summary>
    /// Saves the alerts that changed since they were last saved, and returns the alerts the event must
    /// be raised for.
    /// </summary>
    public IdentityAlert[] Flush( IActivityLineEmitter logger )
    {
        lock( _lock )
        {
            foreach( var id in _dirty )
            {
                if( _alerts.TryGetValue( id, out var a ) ) Save( logger, a );
            }
            _dirty.Clear();
            if( _pending.Count == 0 ) return [];
            var p = _pending.ToArray();
            _pending.Clear();
            return p;
        }
    }

    void Save( IActivityLineEmitter logger, IdentityAlert a )
    {
        try
        {
            var d = new AlertFile( a.Kind, a.Subject, a.IsAboutSelf, a.ReportedBy.ToArray(), a.Seq,
                                   a.ExpectedDigest.ToArray(), a.ObservedDigest.ToArray(), a.FirstSeen, a.LastSeen, a.Count );
            _local.LocalFileStore.CreateDirectory( _folder );
            _local.LocalFileStore.WriteAllBytes( GetPath( a.Id ), JsonSerializer.SerializeToUtf8Bytes( d ) );
        }
        catch( Exception ex )
        {
            // The alert is still in memory and logged: losing its persistence must not lose it altogether.
            logger.Log( LogLevel.Error, _tags, $"Unable to persist identity alert {a}.", ex );
        }
    }

    NormalizedPath GetPath( string id ) => _folder.AppendPart( id + Extension );

    static string ComputeId( IdentityAlertKind kind, string subject, int seq, ReadOnlySpan<byte> observedDigest )
    {
        var key = Encoding.UTF8.GetBytes( $"{kind}|{subject}|{seq}|{Convert.ToHexString( observedDigest )}" );
        return Convert.ToHexString( SHA256.HashData( key ), 0, 12 ).ToLowerInvariant();
    }

    static LogLevel GetLevel( IdentityAlertKind kind ) => kind == IdentityAlertKind.RotationFailing ? LogLevel.Warn : LogLevel.Error;

    static string GetAdvice( IdentityAlertKind kind, string subject ) => kind switch
    {
        IdentityAlertKind.IdentityTakenOver
            => "Someone rotated this identity, which requires its committed next key: the identity is lost to them. "
               + "Recovery is a new identity that every remote re-approves.",
        IdentityAlertKind.IdentityForked
            => "Someone wrote an event of this identity, which requires one of its committed keys: that key leaked. "
               + "Recovery is a new identity that every remote re-approves.",
        IdentityAlertKind.RemoteDuplicity
            => $"Two validly signed events exist at the same position of the log of '{subject}': its committed key leaked. "
               + "Its identity must be re-created and re-approved.",
        IdentityAlertKind.NextKeyLost
            => "This party can neither rotate nor be revoked. The current key keeps working. "
               + "Recovery is a new identity that every remote re-approves.",
        _ => "Its current key stays in use beyond its schedule."
    };
}
