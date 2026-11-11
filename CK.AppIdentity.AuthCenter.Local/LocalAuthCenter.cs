using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
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
public sealed class LocalAuthCenter : IAuthCenterProofChecker, IPartyEncryptionKeyDirectory
{
    readonly CrisAuthCenter _center;
    readonly ILocalParty _party;
    readonly AuthCenterOptions _options;
    readonly AuthCenterSessionStore _sessions;
    readonly AuthCenterPendingStore<PendingRemoteLogin> _pendingRemoteLogins;

    readonly ImmutableConfigurationSection? _settings;
    readonly RouteHosts? _configuredRouteHosts;

    internal LocalAuthCenter( IActivityMonitor monitor,
                              CrisAuthCenter center,
                              AuthCenterOptions options,
                              ImmutableConfigurationSection? settings,
                              RouteHosts? configuredRouteHosts )
    {
        Throw.DebugAssert( center.AuthCenter == center.Owner );
        _center = center;
        var party = _party = center.Owner;
        _options = options;
        _settings = settings;
        _configuredRouteHosts = configuredRouteHosts;
        _sessions = new AuthCenterSessionStore( party.LocalFileStore );
        _sealNonces = new AuthCenterSealNonces( monitor,
                                                party.LocalFileStore,
                                                party.LocalFileStore.FolderPath.Combine( SealNoncesPath ),
                                                party.ApplicationIdentityService.SystemClock.UtcNow );
        _pendingRemoteLogins = new AuthCenterPendingStore<PendingRemoteLogin>( PendingRemoteLoginLifetime, MaxPendingRemoteLogins );
        party.ApplicationIdentityService.Heartbeat.Async += OnHeartbeatAsync;
        // The targets of the authorized hosts follow what the hosts announce.
        party.DescriptionChanged.Async += ( m, p, cancel ) => SyncRouteHostsInBackground();
        party.RemoteDescriptionChanged.Async += ( m, r, cancel ) => SyncRouteHostsInBackground();
        _ = party.ApplicationIdentityService.InitializationTask.ContinueWith( _ => SyncRouteHostsInBackground(), TaskScheduler.Default );
    }

    Task SyncRouteHostsInBackground()
    {
        _ = Task.Run( async () =>
        {
            var m = new ActivityMonitor( $"AuthCenter '{_party}': the route hosts." );
            try
            {
                await SyncRouteHostsAsync( m ).ConfigureAwait( false );
            }
            catch( Exception ex )
            {
                m.Error( "While updating the route hosts.", ex );
            }
            finally
            {
                m.MonitorEnd();
            }
        } );
        return Task.CompletedTask;
    }

    // The configured hosts are always authorized (a configured target is fixed); the targets of the other ones follow what
    // their hosts announce, when this center sees their description. A new list is signed only when something changed.
    // A revoked configured host is not authorized (see AuthCenterSystemList.UpdateAsync, that serializes the updates).
    async Task SyncRouteHostsAsync( IActivityMonitor monitor )
    {
        if( _party.GetFeature<AuthCenterSystemList>() is not { } list ) return;
        await list.UpdateAsync( monitor, ( entries, hosts ) =>
        {
            var result = new Dictionary<(string, string), RouteHost>();
            foreach( var h in hosts ) result[(h.RouteName, h.Host)] = h;
            if( _configuredRouteHosts != null )
            {
                foreach( var c in _configuredRouteHosts.Entries ) result.TryAdd( (c.RouteName, c.Host), c );
            }
            foreach( var key in result.Keys.ToList() )
            {
                var h = result[key];
                if( _configuredRouteHosts?.Find( h.RouteName, h.Host ) is { Target: not null } fixedTarget )
                {
                    result[key] = fixedTarget;
                }
                else
                {
                    var target = AuthCenterSystemList.FindAnnouncedTarget( _party, h.RouteName, h.Host, out var seen );
                    if( seen ) result[key] = h with { Target = target };
                }
            }
            return (entries, result.Values.ToList());
        } ).ConfigureAwait( false );
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
                try
                {
                    _sealNonces.Compact( m, DateTime.UtcNow );
                }
                catch( Exception ex )
                {
                    m.Error( "While compacting the journal of the seal nonces.", ex );
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

    /// <summary>
    /// Gets the local Authentication Center of a remote: the caller is a remote of a local party that is its own
    /// Authentication Center, and it allows "AuthCenterRemote" (it then shares its <see cref="CrisAuthCenter"/>).
    /// </summary>
    /// <param name="caller">The remote.</param>
    /// <returns>The local Authentication Center or null.</returns>
    public static LocalAuthCenter? GetLocal( IRemoteParty caller )
    {
        return caller.GetFeature<CrisAuthCenter>() is { } center && center.Owner == caller.Owner
                ? caller.Owner.GetFeature<LocalAuthCenter>()
                : null;
    }

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
    /// <param name="sessionParty">The full name of the party that opened the session (see <see cref="AuthCenterSession.SessionParty"/>).</param>
    /// <param name="bindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
    /// <param name="info">The authentication.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The token.</returns>
    public string CreateToken( string sessionId, string sessionParty, byte[] bindingSecretHash, AuthenticationInfo info, DateTime utcNow )
    {
        Throw.CheckArgument( AuthCenterSession.IsValidSessionId( sessionId ) );
        Throw.CheckNotNullOrEmptyArgument( sessionParty );
        Throw.CheckArgument( !info.UnsafeActualActor.IsAnonymous );
        var expiration = utcNow + _options.TokenLifetime;
        if( info.Expires.HasValue && info.Expires.Value < expiration ) expiration = info.Expires.Value;
        return AuthCenterToken.Create( _party.GetRequiredFeature<ILocalKeys>(), _party.FullName, sessionParty, sessionId, bindingSecretHash, info, expiration );
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
    public ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, byte[] bindingSecretHash )
        => CheckProofAsync( monitor, token, bindingSecretHash, null, _party.FullName.Path );

    /// <summary>
    /// Checks a user's proof (see <see cref="CheckProofAsync(IActivityMonitor, string, byte[])"/>) and, for the proof of a
    /// routed command, its seal: the session party sealed the command for the <paramref name="destination"/>.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <param name="seal">The seal of the routed command that carried the proof, null for a proof received directly.</param>
    /// <param name="destination">The full name of the party that received the proof: the destination of a routed command.</param>
    /// <returns>The proved identity, or null when the proof is not valid (the reason is logged).</returns>
    public async ValueTask<AuthenticationInfo?> CheckProofAsync( IActivityMonitor monitor, string token, byte[] bindingSecretHash, RoutedProofSeal? seal, string destination )
    {
        var read = await _center.ReadProofAsync( monitor, token, bindingSecretHash, DateTime.UtcNow ).ConfigureAwait( false );
        if( read == null )
        {
            monitor.Warn( "An invalid user's proof is ignored." );
            return null;
        }
        return await CheckAsync( monitor, token, read, seal, destination ).ConfigureAwait( false );
    }

    /// <summary>
    /// Checks that the session of a proof that has been read is alive and is still the token's and, for the proof of a
    /// routed command received here, its seal (see <see cref="IAuthCenterProofChecker.CheckLivenessAsync"/>): this
    /// Authentication Center reads its session store and has the keys of the session party.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="token">The user's token.</param>
    /// <param name="read">The content of the token, read with its binding secret.</param>
    /// <param name="seal">The seal of the routed command that carried the proof, null for a proof received directly.</param>
    /// <returns>The proved identity, or null when the session ended or changed, or the seal is invalid (the reason is logged).</returns>
    public ValueTask<AuthenticationInfo?> CheckLivenessAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal? seal )
        => CheckAsync( monitor, token, read, seal, _party.FullName.Path );

    async ValueTask<AuthenticationInfo?> CheckAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal? seal, string destination )
    {
        Throw.CheckNotNullArgument( token );
        Throw.CheckNotNullArgument( read );
        if( seal != null && !await CheckSealAsync( monitor, token, read, seal, destination ).ConfigureAwait( false ) )
        {
            return null;
        }
        var utcNow = DateTime.UtcNow;
        var session = await _sessions.TryReadAsync( monitor, read.Info.UnsafeActualActor.ActorId, read.SessionId ).ConfigureAwait( false );
        if( session == null
            || session.Expires <= utcNow
            || session.ActorId != read.Info.UnsafeActor.ActorId
            || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals( session.BindingSecretHash, read.BindingSecretHash ) )
        {
            monitor.Warn( "The token of a session that ended or changed is ignored." );
            return null;
        }
        return read.Info;
    }

    /// <summary>
    /// Gets the verified encryption key of this Authentication Center's party or of one of its remotes (see
    /// <see cref="IPartyEncryptionKeyDirectory"/>): the key a remote publishes in its description, verified with its
    /// pinned keys (its key events are requested once when its signer is unknown here).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <returns>The public key and the end of its use, or null when it is unknown (the reason is logged).</returns>
    public async ValueTask<(byte[] PublicKey, DateTime Expires)?> GetPartyEncryptionKeyAsync( IActivityMonitor monitor, string partyFullName )
    {
        Throw.CheckNotNullArgument( partyFullName );
        var utcNow = DateTime.UtcNow;
        if( partyFullName == _party.FullName.Path )
        {
            var own = _party.GetRequiredFeature<ILocalKeys>().GetEncryptionKey( utcNow );
            return ApplicationSignature.TryRead( own.Signature.Span, out var signature )
                    ? (own.PublicKey.ToArray(), signature.Expiration)
                    : null;
        }
        var remote = _party.Remotes.FirstOrDefault( r => r.FullName.Path == partyFullName );
        var published = remote?.Description.EncryptionKey;
        var keys = remote?.GetFeature<IPartyKeys>();
        if( remote == null || published == null || keys == null )
        {
            monitor.Warn( remote == null
                            ? $"'{partyFullName}' is not a remote of the Authentication Center '{_party}': its encryption key is unknown."
                            : $"'{partyFullName}' publishes no encryption key (it is not connected, or it has no key management)." );
            return null;
        }
        var verdict = PartyEncryption.Check( monitor, keys, published, out var publicKey, out var expires );
        if( verdict == SignatureVerdict.UnknownIssuer
            && remote.GetFeature<CK.AppIdentity.TransportLayer.TransportFeature>() is { } transport
            && await transport.RequestKeyEventsAsync( CrisAuthCenter.KeyEventsTimeout ).ConfigureAwait( false ) )
        {
            verdict = PartyEncryption.Check( monitor, keys, published, out publicKey, out expires );
        }
        if( verdict != SignatureVerdict.Valid || expires <= utcNow )
        {
            monitor.Warn( $"The encryption key published by '{partyFullName}' is refused." );
            return null;
        }
        return (publicKey!, expires);
    }

    /// <summary>
    /// The path of the journal of the nonces of the seals that have been used, in the local store (see <see cref="CheckSealAsync"/>).
    /// </summary>
    public const string SealNoncesPath = "AuthCenter/SealNonces.journal";

    // The nonces of the seals that have been used, until the end of their lifetime (journaled: a restart forgets nothing).
    readonly AuthCenterSealNonces _sealNonces;

    // Checks the seal of a routed command: made by the session party, for this destination, with this proof, used once.
    async ValueTask<bool> CheckSealAsync( IActivityMonitor monitor, string token, AuthCenterTokenContent read, RoutedProofSeal seal, string destination )
    {
        var utcNow = DateTime.UtcNow;
        bool valid = RoutedCommandSeal.CheckHeader( monitor, seal.Header, destination, token, utcNow, out var nonce, out var created );
        if( valid )
        {
            var signer = read.SessionParty == _party.FullName.Path
                            ? _party
                            : (IParty?)_party.Remotes.FirstOrDefault( r => r.FullName.Path == read.SessionParty );
            var keys = signer?.GetFeature<IPartyKeys>();
            if( keys == null || !ApplicationSignature.TryRead( seal.Signature, out var signature ) )
            {
                monitor.Warn( keys == null
                                ? $"Routed command seal refused: the session party '{read.SessionParty}' is not known here."
                                : "Routed command seal refused: its signature is malformed." );
                valid = false;
            }
            else
            {
                var data = RoutedCommandSeal.GetSignedData( seal.Header, seal.PayloadDigest );
                var verdict = keys.Check( monitor, RoutedCommandSeal.Purpose, data, signature );
                // The session party may have rotated its key: its key events are requested, once.
                if( verdict == SignatureVerdict.UnknownIssuer
                    && signer!.GetFeature<CK.AppIdentity.TransportLayer.TransportFeature>() is { } transport
                    && await transport.RequestKeyEventsAsync( CrisAuthCenter.KeyEventsTimeout ).ConfigureAwait( false ) )
                {
                    verdict = keys.Check( monitor, RoutedCommandSeal.Purpose, data, signature );
                }
                valid = verdict == SignatureVerdict.Valid;
                if( valid && !_sealNonces.TryUse( monitor, nonce!, created + RoutedCommandSeal.Lifetime + RoutedCommandSeal.ClockSkew, utcNow ) )
                {
                    monitor.Warn( "Routed command seal refused: it has already been used." );
                    valid = false;
                }
            }
        }
        if( !valid )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The seal of a command routed to '{destination}' with a proof of a session opened by '{read.SessionParty}' is invalid: the proof is refused." );
        }
        return valid;
    }


}
