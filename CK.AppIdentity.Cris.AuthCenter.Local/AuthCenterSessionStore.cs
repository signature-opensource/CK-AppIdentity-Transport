using CK.Core;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Stores the <see cref="AuthCenterSession"/> of a local Authentication Center in its <see cref="ILocalParty.LocalFileStore"/>:
/// "AuthCenter/Sessions/{ActualActorId}/{SessionId}". All the sessions of an actor are in one folder (to revoke them all).
/// <para>
/// The format is the Authentication Center's one, with its own version number.
/// </para>
/// </summary>
public sealed class AuthCenterSessionStore
{
    // Version 2: the previous secrets and the rotation time (a version 1 file has none).
    const int _version = 2;
    readonly System.Collections.Generic.Dictionary<string, SessionLock> _locks = new();
    readonly IFileStore _store;
    readonly NormalizedPath _root;

    internal AuthCenterSessionStore( IFileStore store )
    {
        _store = store;
        _root = store.FolderPath.Combine( "AuthCenter/Sessions" );
    }

    NormalizedPath GetPath( int actualActorId, string sessionId )
    {
        Throw.CheckArgument( actualActorId != 0 );
        Throw.CheckArgument( AuthCenterSession.IsValidSessionId( sessionId ) );
        return _root.AppendPart( actualActorId.ToString( System.Globalization.CultureInfo.InvariantCulture ) ).AppendPart( sessionId );
    }

    /// <summary>
    /// Saves a session (creates or replaces it).
    /// </summary>
    /// <param name="session">The session to save.</param>
    /// <param name="cancel">Optional cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public async Task SaveAsync( AuthCenterSession session, CancellationToken cancel = default )
    {
        var path = GetPath( session.ActualActorId, session.SessionId );
        _store.CreateDirectory( path.RemoveLastPart() );
        try
        {
            await WriteAsync( path, session, cancel ).ConfigureAwait( false );
        }
        catch( DirectoryNotFoundException )
        {
            // The purge deleted the (empty) actor folder in the meantime.
            _store.CreateDirectory( path.RemoveLastPart() );
            await WriteAsync( path, session, cancel ).ConfigureAwait( false );
        }
    }

    Task WriteAsync( NormalizedPath path, AuthCenterSession session, CancellationToken cancel )
    {
        return _store.WriteAtomicallyAsync( path, async ( stream, c ) =>
        {
            await using var w = new Utf8JsonWriter( stream );
            w.WriteStartObject();
            w.WriteNumber( "Version", _version );
            w.WriteString( "SessionId", session.SessionId );
            w.WriteNumber( "ActualActorId", session.ActualActorId );
            w.WriteNumber( "ActorId", session.ActorId );
            w.WriteString( "Created", session.Created );
            w.WriteString( "Expires", session.Expires );
            w.WriteBoolean( "RememberMe", session.RememberMe );
            w.WriteString( "DeviceId", session.DeviceId );
            w.WriteString( "RefreshSecretHash", session.RefreshSecretHash );
            w.WriteString( "BindingSecretHash", session.BindingSecretHash );
            if( session.PreviousRefreshSecretHash != null && session.PreviousBindingSecretHash != null )
            {
                w.WriteString( "PreviousRefreshSecretHash", session.PreviousRefreshSecretHash );
                w.WriteString( "PreviousBindingSecretHash", session.PreviousBindingSecretHash );
            }
            w.WriteString( "RotatedAt", session.RotatedAt );
            w.WriteEndObject();
            await w.FlushAsync( c ).ConfigureAwait( false );
        }, cancel );
    }

    /// <summary>
    /// Reads a session. Returns null if it doesn't exist or cannot be read (the error is logged).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="actualActorId">The actual actor of the session.</param>
    /// <param name="sessionId">The session identifier. It must be valid (see <see cref="AuthCenterSession.IsValidSessionId(string?)"/>).</param>
    /// <param name="cancel">Optional cancellation token.</param>
    /// <returns>The session or null.</returns>
    public async Task<AuthCenterSession?> TryReadAsync( IActivityMonitor monitor, int actualActorId, string sessionId, CancellationToken cancel = default )
    {
        var path = GetPath( actualActorId, sessionId );
        if( !File.Exists( path ) ) return null;
        try
        {
            await using var stream = _store.OpenReadStream( path );
            using var d = await JsonDocument.ParseAsync( stream, cancellationToken: cancel ).ConfigureAwait( false );
            var o = d.RootElement;
            var version = o.GetProperty( "Version" ).GetInt32();
            if( version is < 1 or > _version ) Throw.CKException( $"Unknown session version {version}." );
            var s = new AuthCenterSession( o.GetProperty( "SessionId" ).GetString()!,
                                           o.GetProperty( "ActualActorId" ).GetInt32(),
                                           o.GetProperty( "ActorId" ).GetInt32(),
                                           o.GetProperty( "Created" ).GetDateTime(),
                                           o.GetProperty( "Expires" ).GetDateTime(),
                                           o.GetProperty( "RememberMe" ).GetBoolean(),
                                           o.GetProperty( "DeviceId" ).GetString()!,
                                           o.GetProperty( "RefreshSecretHash" ).GetString()!,
                                           o.GetProperty( "BindingSecretHash" ).GetString()! )
            {
                PreviousRefreshSecretHash = o.TryGetProperty( "PreviousRefreshSecretHash", out var pr ) ? pr.GetString() : null,
                PreviousBindingSecretHash = o.TryGetProperty( "PreviousBindingSecretHash", out var pb ) ? pb.GetString() : null,
                RotatedAt = o.TryGetProperty( "RotatedAt", out var r ) ? r.GetDateTime() : DateTime.MinValue
            };
            if( s.SessionId != sessionId || s.ActualActorId != actualActorId ) Throw.CKException( "The session doesn't match its file." );
            return s;
        }
        catch( Exception ex )
        {
            monitor.Error( $"Unable to read the session '{path}'.", ex );
            return null;
        }
    }

    /// <summary>
    /// Serializes the operations on a session in this process: reading it, checking the presented proof, rotating its
    /// secrets and saving it must be atomic (two concurrent rotations would both match and the last write would win,
    /// revoking the other caller at its next refresh). There is one Authentication Center party per store.
    /// </summary>
    /// <param name="sessionKey">The session key.</param>
    /// <returns>The lock to dispose.</returns>
    public async ValueTask<IDisposable> LockAsync( string sessionKey )
    {
        SessionLock? l;
        lock( _locks )
        {
            if( !_locks.TryGetValue( sessionKey, out l ) ) _locks.Add( sessionKey, l = new SessionLock( this, sessionKey ) );
            ++l.Count;
        }
        await l.Semaphore.WaitAsync().ConfigureAwait( false );
        return l;
    }

    sealed class SessionLock : IDisposable
    {
        readonly AuthCenterSessionStore _store;
        readonly string _key;
        public readonly SemaphoreSlim Semaphore = new SemaphoreSlim( 1, 1 );
        public int Count;

        public SessionLock( AuthCenterSessionStore store, string key )
        {
            _store = store;
            _key = key;
        }

        public void Dispose()
        {
            Semaphore.Release();
            lock( _store._locks )
            {
                if( --Count == 0 ) _store._locks.Remove( _key );
            }
        }
    }

    /// <summary>
    /// Deletes the expired sessions (and the actor folders that become empty).
    /// <para>
    /// Every save writes the session file and a session never ends later than <paramref name="sessionLifetime"/> after it
    /// has been saved: the files written before "now - sessionLifetime" are the candidates, their end is then checked.
    /// A candidate that cannot be read is deleted (it cannot be used anyway).
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="sessionLifetime">The <see cref="AuthCenterOptions.SessionLifetime"/>.</param>
    /// <param name="cancel">Optional cancellation token.</param>
    /// <returns>The number of deleted sessions.</returns>
    public async Task<int> PurgeExpiredAsync( IActivityMonitor monitor, DateTime utcNow, TimeSpan sessionLifetime, CancellationToken cancel = default )
    {
        if( !Directory.Exists( _root ) ) return 0;
        int count = 0;
        var limit = utcNow - sessionLifetime;
        foreach( var actorFolder in Directory.EnumerateDirectories( _root ) )
        {
            if( !int.TryParse( Path.GetFileName( actorFolder ), System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var actorId )
                || actorId == 0 )
            {
                continue;
            }
            foreach( var file in Directory.EnumerateFiles( actorFolder ) )
            {
                cancel.ThrowIfCancellationRequested();
                var sessionId = Path.GetFileName( file );
                if( !AuthCenterSession.IsValidSessionId( sessionId ) || File.GetLastWriteTimeUtc( file ) >= limit ) continue;
                var s = await TryReadAsync( monitor, actorId, sessionId, cancel ).ConfigureAwait( false );
                if( (s == null || s.Expires <= utcNow) && _store.TryTrash( monitor, file, immediateDelete: true ) ) ++count;
            }
            if( !Directory.EnumerateFileSystemEntries( actorFolder ).Any() )
            {
                // A concurrent login may write in it: an error is not an issue (the next purge retries).
                try { Directory.Delete( actorFolder ); } catch( IOException ) { }
            }
        }
        if( count > 0 ) monitor.Info( $"{count} expired sessions purged." );
        return count;
    }

    /// <summary>
    /// Deletes a session if it exists.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="actualActorId">The actual actor of the session.</param>
    /// <param name="sessionId">The session identifier. It must be valid (see <see cref="AuthCenterSession.IsValidSessionId(string?)"/>).</param>
    /// <returns>True if the session has been deleted, false if it didn't exist or cannot be deleted.</returns>
    public bool TryDelete( IActivityMonitor monitor, int actualActorId, string sessionId )
    {
        var path = GetPath( actualActorId, sessionId );
        return File.Exists( path ) && _store.TryTrash( monitor, path, immediateDelete: true );
    }
}
