using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The part of a <see cref="CrisAuthCenter"/> that exists only when this application is the Authentication Center
/// of its local party (see <see cref="CrisAuthCenter.Local"/>): its settings, its sessions and the signing of its tokens.
/// </summary>
public sealed class LocalAuthCenter
{
    readonly ILocalParty _party;
    readonly AuthCenterOptions _options;
    readonly AuthCenterSessionStore _sessions;

    internal LocalAuthCenter( ILocalParty party, AuthCenterOptions options )
    {
        _party = party;
        _options = options;
        _sessions = new AuthCenterSessionStore( party.LocalFileStore );
    }

    /// <summary>
    /// Gets the local party that is the Authentication Center.
    /// </summary>
    public ILocalParty Party => _party;

    /// <summary>
    /// Gets the settings.
    /// </summary>
    public AuthCenterOptions Options => _options;

    /// <summary>
    /// Gets the session store.
    /// </summary>
    public AuthCenterSessionStore Sessions => _sessions;

    /// <summary>
    /// Creates a signed token for a session. It expires after <see cref="AuthCenterOptions.TokenLifetime"/>, or with
    /// the authentication if it ends before.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="info">The authentication.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The token.</returns>
    public string CreateToken( string sessionId, AuthenticationInfo info, DateTime utcNow )
    {
        Throw.CheckArgument( AuthCenterSession.IsValidSessionId( sessionId ) );
        Throw.CheckArgument( !info.UnsafeActualActor.IsAnonymous );
        var expiration = utcNow + _options.TokenLifetime;
        if( info.Expires.HasValue && info.Expires.Value < expiration ) expiration = info.Expires.Value;
        return AuthCenterToken.Create( _party.GetRequiredFeature<ILocalKeys>(), _party.FullName, sessionId, info, expiration );
    }
}
