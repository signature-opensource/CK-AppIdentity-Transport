using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The feature of a local party that is its own Authentication Center: its settings, its sessions and the signing of its
/// tokens. Added by the <see cref="LocalAuthCenterFeatureDriver"/>.
/// </summary>
public sealed class LocalAuthCenter : IAuthCenterProofChecker
{
    readonly CrisAuthCenter _center;
    readonly ILocalParty _party;
    readonly AuthCenterOptions _options;
    readonly AuthCenterSessionStore _sessions;
    readonly AuthCenterEncryptionKeys _encryptionKeys;
    readonly AuthCenterPendingStore<PendingRemoteLogin> _pendingRemoteLogins;

    readonly ImmutableConfigurationSection? _settings;

    internal LocalAuthCenter( IActivityMonitor monitor, CrisAuthCenter center, AuthCenterOptions options, ImmutableConfigurationSection? settings )
    {
        Throw.DebugAssert( center.AuthCenter == center.Owner );
        _center = center;
        var party = _party = center.Owner;
        _options = options;
        _settings = settings;
        _sessions = new AuthCenterSessionStore( party.LocalFileStore );
        _encryptionKeys = new AuthCenterEncryptionKeys( monitor, party );
        _pendingRemoteLogins = new AuthCenterPendingStore<PendingRemoteLogin>( PendingRemoteLoginLifetime, MaxPendingRemoteLogins );
        party.ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
    }

    /// <summary>
    /// Gets the configuration sub-section of a scheme family ("AuthCenter:Oidc" for "Oidc"): the families read their own
    /// settings. The key must be declared by an <see cref="IAuthCenterSchemeConfiguration"/>.
    /// </summary>
    /// <param name="key">The family's key ("Oidc").</param>
    /// <returns>The section or null when it is not configured.</returns>
    public ImmutableConfigurationSection? GetSchemeSettings( string key ) => _settings?.TryGetSection( key );

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
    /// Gets the shared <see cref="CrisAuthCenter"/> feature (its <see cref="CrisAuthCenter.AuthCenter"/> is the <see cref="Party"/>).
    /// </summary>
    public CrisAuthCenter Center => _center;

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

    /// <summary>
    /// Checks a user's proof (see <see cref="IAuthCenterProofChecker"/>): a token of this Authentication Center, presented
    /// with the binding secret of its session, whose session is alive and is still the token's (the same binding and the
    /// same actor: a refresh rotates the binding, a logout or a revocation deletes the session, an impersonation started
    /// or ended since the token was issued changes the actor). Used for the proofs received here, and for the ones that
    /// the remotes ask to verify (<c>IVerifyCallerProofCommand</c>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, string bindingSecretHash )
    {
        var read = await _center.ReadProofAsync( monitor, token, bindingSecretHash, DateTime.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( "An invalid user's proof is ignored." );
            return null;
        }
        return await CheckLivenessAsync( monitor, token, read ).ConfigureAwait( false );
    }

    /// <summary>
    /// Checks that the session of a proof that has been read is alive and is still the token's (see
    /// <see cref="IAuthCenterProofChecker.CheckLivenessAsync"/>): this Authentication Center reads its session store.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token (unused here: the read content is enough).</param>
    /// <param name="read">The content of the token, read with its binding secret.</param>
    /// <returns>The proved identity, or null when the session ended or changed (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckLivenessAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read )
    {
        Throw.CheckNotNullArgument( read );
        var utcNow = DateTime.UtcNow;
        var session = await _sessions.TryReadAsync( monitor, read.Info.UnsafeActualActor.ActorId, read.SessionId ).ConfigureAwait( false );
        if( session == null
            || session.Expires <= utcNow
            || session.ActorId != read.Info.UnsafeActor.ActorId
            || !FixedTimeEquals( session.BindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( "The token of a session that ended or changed is ignored." );
            return null;
        }
        return read.Info;
    }

    static bool FixedTimeEquals( string a, string b ) => System.Security.Cryptography.CryptographicOperations.FixedTimeEquals( System.Text.Encoding.ASCII.GetBytes( a ), System.Text.Encoding.ASCII.GetBytes( b ) );
}
