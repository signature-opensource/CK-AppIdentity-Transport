using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
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
    readonly AuthCenterPendingStore<PendingRemoteLogin> _pendingRemoteLogins;

    internal LocalAuthCenter( IActivityMonitor monitor, ILocalParty party, AuthCenterOptions options )
    {
        _party = party;
        _options = options;
        _sessions = new AuthCenterSessionStore( party.LocalFileStore );
        _encryptionKeys = new AuthCenterEncryptionKeys( monitor, party );
        _pendingRemoteLogins = new AuthCenterPendingStore<PendingRemoteLogin>( PendingRemoteLoginLifetime, MaxPendingRemoteLogins );
        party.AddFeature( new AuthCenterOidc( options.OidcSchemes ) );
        party.ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
    }

    /// <summary>
    /// The lifetime of a pending remote login: 10 minutes.
    /// </summary>
    public static readonly TimeSpan PendingRemoteLoginLifetime = TimeSpan.FromMinutes( 10 );

    /// <summary>
    /// The maximal number of pending remote logins: 10,000. Starting a login is anonymous: this bounds the memory.
    /// </summary>
    public const int MaxPendingRemoteLogins = 10_000;

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
    /// Gets the remote logins that have started and wait for their callback, under their state.
    /// </summary>
    public AuthCenterPendingStore<PendingRemoteLogin> PendingRemoteLogins => _pendingRemoteLogins;

    /// <summary>
    /// Gets the scheme families of this Authentication Center (the <see cref="IAuthCenterScheme"/> features of its party).
    /// </summary>
    public IEnumerable<IAuthCenterScheme> SchemeFamilies => _party.Features.OfType<IAuthCenterScheme>();

    /// <summary>
    /// Finds the family of a scheme.
    /// </summary>
    /// <param name="scheme">The scheme ("Oidc.Google" for instance).</param>
    /// <returns>The family or null if no family makes this scheme available.</returns>
    public IAuthCenterScheme? FindSchemeFamily( string scheme )
    {
        return SchemeFamilies.FirstOrDefault( f => f.Schemes.Contains( scheme, StringComparer.OrdinalIgnoreCase ) );
    }

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
