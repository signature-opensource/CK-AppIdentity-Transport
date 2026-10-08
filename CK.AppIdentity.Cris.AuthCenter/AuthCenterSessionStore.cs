using CK.Core;
using System;
using System.IO;
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
    const int _version = 1;
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
    public Task SaveAsync( AuthCenterSession session, CancellationToken cancel = default )
    {
        var path = GetPath( session.ActualActorId, session.SessionId );
        _store.CreateDirectory( path.RemoveLastPart() );
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
            if( version != _version ) Throw.CKException( $"Unknown session version {version}." );
            var s = new AuthCenterSession( o.GetProperty( "SessionId" ).GetString()!,
                                           o.GetProperty( "ActualActorId" ).GetInt32(),
                                           o.GetProperty( "ActorId" ).GetInt32(),
                                           o.GetProperty( "Created" ).GetDateTime(),
                                           o.GetProperty( "Expires" ).GetDateTime(),
                                           o.GetProperty( "RememberMe" ).GetBoolean(),
                                           o.GetProperty( "DeviceId" ).GetString()!,
                                           o.GetProperty( "RefreshSecretHash" ).GetString()!,
                                           o.GetProperty( "BindingSecretHash" ).GetString()! );
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
