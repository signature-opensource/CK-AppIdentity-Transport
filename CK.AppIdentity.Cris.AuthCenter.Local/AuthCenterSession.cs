using CK.Core;
using System;
using System.Buffers.Text;
using System.Security.Cryptography;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// A session of a local Authentication Center. It holds the hashes of the secrets of the endpoint that opened it,
/// never the secrets.
/// </summary>
/// <param name="SessionId">The session identifier (see <see cref="NewSessionId"/>).</param>
/// <param name="ActualActorId">The actual actor: the one that logged in.</param>
/// <param name="ActorId">The actor (the <paramref name="ActualActorId"/> when not impersonated).</param>
/// <param name="Created">The creation time (Utc).</param>
/// <param name="Expires">The end of the session (Utc).</param>
/// <param name="RememberMe">Whether the session survives the end of the caller session.</param>
/// <param name="DeviceId">The device identifier.</param>
/// <param name="RefreshSecretHash">The hash of the refresh secret of the endpoint.</param>
/// <param name="BindingSecretHash">The hash of the binding secret of the endpoint.</param>
public sealed record AuthCenterSession( string SessionId,
                                        int ActualActorId,
                                        int ActorId,
                                        DateTime Created,
                                        DateTime Expires,
                                        bool RememberMe,
                                        string DeviceId,
                                        string RefreshSecretHash,
                                        string BindingSecretHash )
{
    /// <summary>
    /// The length of a session identifier: 16 random bytes in base64url.
    /// </summary>
    public const int SessionIdLength = 22;

    /// <summary>
    /// Gets the hash of the previous refresh secret: the one replaced by the last rotation. Null when there is none, or
    /// when it has been used (it is accepted once, see <see cref="MatchesPrevious"/>).
    /// </summary>
    public string? PreviousRefreshSecretHash { get; init; }

    /// <summary>
    /// Gets the hash of the previous binding secret (see <see cref="PreviousRefreshSecretHash"/>).
    /// </summary>
    public string? PreviousBindingSecretHash { get; init; }

    /// <summary>
    /// Gets the time of the last rotation of the secrets (Utc). <see cref="DateTime.MinValue"/> before the first one.
    /// </summary>
    public DateTime RotatedAt { get; init; }

    /// <summary>
    /// Gets the session key that the endpoint keeps and presents back: "{ActualActorId}.{SessionId}".
    /// It is not a secret (the token holds the session identifier).
    /// </summary>
    public string SessionKey => GetSessionKey( ActualActorId, SessionId );

    /// <summary>
    /// Gets the session key of a session (see <see cref="SessionKey"/>).
    /// </summary>
    /// <param name="actualActorId">The actual actor identifier.</param>
    /// <param name="sessionId">The session identifier.</param>
    /// <returns>The session key.</returns>
    public static string GetSessionKey( int actualActorId, string sessionId ) => $"{actualActorId.ToString( System.Globalization.CultureInfo.InvariantCulture )}.{sessionId}";

    /// <summary>
    /// Parses a session key (see <see cref="SessionKey"/>) presented by an endpoint.
    /// </summary>
    /// <param name="sessionKey">The session key.</param>
    /// <param name="actualActorId">The actual actor identifier.</param>
    /// <param name="sessionId">The session identifier.</param>
    /// <returns>True if the key is valid.</returns>
    public static bool TryParseSessionKey( string? sessionKey, out int actualActorId, [System.Diagnostics.CodeAnalysis.NotNullWhen( true )] out string? sessionId )
    {
        actualActorId = 0;
        sessionId = null;
        if( sessionKey == null ) return false;
        int dot = sessionKey.IndexOf( '.' );
        if( dot <= 0 ) return false;
        var id = sessionKey.Substring( dot + 1 );
        if( !IsValidSessionId( id )
            || !int.TryParse( sessionKey.AsSpan( 0, dot ), System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out actualActorId )
            || actualActorId == 0 )
        {
            actualActorId = 0;
            return false;
        }
        sessionId = id;
        return true;
    }

    /// <summary>
    /// Checks that a presented proof matches this session: same key and same secret hashes (compared in constant time).
    /// </summary>
    /// <param name="proof">The presented proof.</param>
    /// <returns>True if the proof matches this session.</returns>
    public bool Matches( CK.Auth.AuthenticationSessionProof proof )
    {
        return proof.SessionKey == SessionKey
               && FixedTimeEquals( proof.RefreshSecretHash, RefreshSecretHash )
               && FixedTimeEquals( proof.BindingSecretHash, BindingSecretHash );
    }

    /// <summary>
    /// Checks that a presented proof matches the previous secrets of this session (the ones replaced by the last
    /// rotation), still in their grace window and not used yet: the answer of the rotation may have been lost.
    /// </summary>
    /// <param name="proof">The presented proof.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="graceWindow">The <see cref="AuthCenterOptions.RefreshGraceWindow"/>.</param>
    /// <returns>True if the proof matches the previous secrets in their grace window.</returns>
    public bool MatchesPrevious( CK.Auth.AuthenticationSessionProof proof, DateTime utcNow, TimeSpan graceWindow )
    {
        return PreviousRefreshSecretHash != null
               && PreviousBindingSecretHash != null
               && utcNow < RotatedAt + graceWindow
               && proof.SessionKey == SessionKey
               && FixedTimeEquals( proof.RefreshSecretHash, PreviousRefreshSecretHash )
               && FixedTimeEquals( proof.BindingSecretHash, PreviousBindingSecretHash );
    }

    /// <summary>
    /// Rotates the secrets: the new hashes become the current ones. The current ones become the previous ones, unless
    /// the rotation is done <paramref name="fromPrevious"/>: the previous secrets are then used (cleared).
    /// </summary>
    /// <param name="refreshSecretHash">The hash of the new refresh secret.</param>
    /// <param name="bindingSecretHash">The hash of the new binding secret.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="fromPrevious">True when the caller presented the previous secrets (see <see cref="MatchesPrevious"/>).</param>
    /// <returns>The rotated session.</returns>
    public AuthCenterSession Rotate( string refreshSecretHash, string bindingSecretHash, DateTime utcNow, bool fromPrevious )
    {
        return this with
        {
            RefreshSecretHash = refreshSecretHash,
            BindingSecretHash = bindingSecretHash,
            PreviousRefreshSecretHash = fromPrevious ? null : RefreshSecretHash,
            PreviousBindingSecretHash = fromPrevious ? null : BindingSecretHash,
            RotatedAt = utcNow
        };
    }

    static bool FixedTimeEquals( string a, string b )
        => CryptographicOperations.FixedTimeEquals( System.Text.Encoding.UTF8.GetBytes( a ), System.Text.Encoding.UTF8.GetBytes( b ) );

    /// <summary>
    /// Creates a new random session identifier.
    /// </summary>
    /// <returns>A new session identifier.</returns>
    public static string NewSessionId() => Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 16 ) );

    /// <summary>
    /// Checks a session identifier: it comes from a token or a client and is used as a file name.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <returns>True if it is a valid session identifier.</returns>
    public static bool IsValidSessionId( string? sessionId )
    {
        if( sessionId == null || sessionId.Length != SessionIdLength ) return false;
        foreach( var c in sessionId )
        {
            if( !char.IsAsciiLetterOrDigit( c ) && c != '-' && c != '_' ) return false;
        }
        return true;
    }
}
