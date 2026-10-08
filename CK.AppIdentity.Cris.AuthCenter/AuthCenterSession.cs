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
