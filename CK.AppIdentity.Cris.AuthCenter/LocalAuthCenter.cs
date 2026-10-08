using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Threading;
using System.Threading.Tasks;

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
    readonly AuthCenterEncryptionKeys _encryptionKeys;
    readonly AuthCenterOidc _oidc;

    internal LocalAuthCenter( IActivityMonitor monitor, ILocalParty party, AuthCenterOptions options )
    {
        _party = party;
        _options = options;
        _sessions = new AuthCenterSessionStore( party.LocalFileStore );
        _encryptionKeys = new AuthCenterEncryptionKeys( monitor, party );
        _oidc = new AuthCenterOidc();
        party.ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
    }

    /// <summary>
    /// The period of the purge of the expired sessions: 1 hour.
    /// </summary>
    public static readonly TimeSpan PurgePeriod = TimeSpan.FromHours( 1 );

    DateTime _nextPurge;
    int _purging;

    // The heartbeat runs on the agent loop: the purge (that enumerates files) runs in the background.
    Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount, CancellationToken cancel )
    {
        var utcNow = DateTime.UtcNow;
        if( utcNow >= _nextPurge && Interlocked.CompareExchange( ref _purging, 1, 0 ) == 0 )
        {
            _nextPurge = utcNow + PurgePeriod;
            _ = Task.Run( async () =>
            {
                var m = new ActivityMonitor( $"AuthCenter '{_party}' session purge." );
                try
                {
                    await _sessions.PurgeExpiredAsync( m, DateTime.UtcNow, _options.SessionLifetime ).ConfigureAwait( false );
                }
                catch( Exception ex )
                {
                    m.Error( "While purging the expired sessions.", ex );
                }
                finally
                {
                    m.MonitorEnd();
                    _purging = 0;
                }
            } );
        }
        return Task.CompletedTask;
    }

    internal AuthCenterEncryptionKeys EncryptionKeys => _encryptionKeys;

    internal void OnTeardown() => _party.ApplicationIdentityService.Heartbeat.Async -= OnHeartbeatAsync;

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
    /// Gets the OpenID Connect client (see <see cref="AuthCenterOptions.OidcSchemes"/>).
    /// </summary>
    public AuthCenterOidc Oidc => _oidc;

    /// <summary>
    /// Creates a signed token for a session. It expires after <see cref="AuthCenterOptions.TokenLifetime"/>, or with
    /// the authentication if it ends before.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
    /// <param name="info">The authentication.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The token.</returns>
    public string CreateToken( string sessionId, string bindingSecretHash, AuthenticationInfo info, DateTime utcNow )
    {
        Throw.CheckArgument( AuthCenterSession.IsValidSessionId( sessionId ) );
        Throw.CheckArgument( !info.UnsafeActualActor.IsAnonymous );
        var expiration = utcNow + _options.TokenLifetime;
        if( info.Expires.HasValue && info.Expires.Value < expiration ) expiration = info.Expires.Value;
        return AuthCenterToken.Create( _party.GetRequiredFeature<ILocalKeys>(), _party.FullName, sessionId, bindingSecretHash, info, expiration );
    }
}
