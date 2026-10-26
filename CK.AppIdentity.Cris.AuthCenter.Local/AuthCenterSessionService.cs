using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The session commands of a local Authentication Center (see <see cref="AuthCenterCommandHandlers"/>): they act on
/// "the current session", the one whose proof is presented by the <see cref="IAuthenticationSessionEndpoint"/>.
/// <para>
/// A presented proof must match the stored session exactly (the session key and both secret hashes). A proof with the
/// right key but other secrets revokes the session: a refresh secret is used once, a rotated secret presented again
/// means that it has been stolen (or that two copies of the caller compete).
/// </para>
/// </summary>
public sealed class AuthCenterSessionService : IScopedAutoService
{
    readonly CurrentLocalParty _localParty;
    readonly AuthenticationInfo _current;
    readonly IAuthenticationSessionEndpoint _endpoint;
    readonly IActorInfoProvider _actors;
    readonly IServiceProvider _services;

    /// <summary>
    /// Initializes a new session service.
    /// </summary>
    /// <param name="localParty">The current local party: its Authentication Center must be local.</param>
    /// <param name="current">The current authentication.</param>
    /// <param name="endpoint">The endpoint that received the command.</param>
    /// <param name="actors">The actor provider: a refresh reads the actors again.</param>
    /// <param name="services">The services, for the optional <see cref="IImpersonationService"/>.</param>
    public AuthCenterSessionService( CurrentLocalParty localParty,
                                     AuthenticationInfo current,
                                     IAuthenticationSessionEndpoint endpoint,
                                     IActorInfoProvider actors,
                                     IServiceProvider services )
    {
        _localParty = localParty;
        _current = current;
        _endpoint = endpoint;
        _actors = actors;
        _services = services;
    }

    // FromPrevious: the proof matched the previous secrets of the session (in their grace window).
    readonly record struct Current( LocalAuthCenter Center, AuthCenterSession Session, bool FromPrevious );

    // Serializes the operations on the presented session (see AuthCenterSessionStore.LockAsync). Null when there is no
    // local AuthCenter or no presented session: GetCurrentAsync then fails.
    async ValueTask<IDisposable?> LockAsync()
    {
        var center = _localParty.LocalParty.GetFeature<LocalAuthCenter>();
        var key = _endpoint.PresentedProof?.SessionKey;
        return center == null || key == null ? null : await center.Sessions.LockAsync( key ).ConfigureAwait( false );
    }

    // Finds the local AuthCenter and the session of the presented proof.
    // The previous secrets of the session (in their grace window, see AuthCenterOptions.RefreshGraceWindow) are accepted
    // when acceptPrevious is true: by the operations that rotate the secrets again (or end the session). Otherwise they
    // are refused without revoking the session: not a theft signal in the window, but not a usable proof either.
    async ValueTask<(Current? Current, string? Error, string? ResName)> GetCurrentAsync( IActivityMonitor monitor, bool revokeOnMismatch, bool acceptPrevious )
    {
        var center = _localParty.LocalParty.GetFeature<LocalAuthCenter>();
        if( center == null ) return (null, $"'{_localParty.LocalParty}' has no AuthCenter.", "Authentication.NoAuthCenter");
        var proof = _endpoint.PresentedProof;
        if( proof == null ) return (null, "No session.", "Authentication.NoSession");
        if( !AuthCenterSession.TryParseSessionKey( proof.SessionKey, out var actualActorId, out var sessionId ) )
        {
            return (null, "Invalid session.", "Authentication.InvalidSession");
        }
        var store = center.Sessions;
        var session = await store.TryReadAsync( monitor, actualActorId, sessionId ).ConfigureAwait( false );
        if( session == null ) return (null, "Invalid session.", "Authentication.InvalidSession");
        bool fromPrevious = false;
        if( !session.Matches( proof ) && session.MatchesPrevious( proof, DateTime.UtcNow, center.Options.RefreshGraceWindow ) )
        {
            if( !acceptPrevious ) return (null, "Invalid session.", "Authentication.InvalidSession");
            monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"The previous secrets of the session of actor #{actualActorId} are used (the answer of its last rotation may have been lost): accepted once." );
            fromPrevious = true;
        }
        else if( !session.Matches( proof ) )
        {
            if( revokeOnMismatch )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"The secrets presented for the session of actor #{actualActorId} don't match: the session is revoked." );
                store.TryDelete( monitor, actualActorId, sessionId );
            }
            return (null, "Invalid session.", "Authentication.InvalidSession");
        }
        if( session.Expires <= DateTime.UtcNow )
        {
            store.TryDelete( monitor, actualActorId, sessionId );
            return (null, "The session expired.", "Authentication.SessionExpired");
        }
        return (new Current( center, session, fromPrevious ), null, null);
    }

    /// <summary>
    /// Gets the current session when its authentication is at the <see cref="AuthLevel.Critical"/> level and not
    /// impersonated: what an operation that adds a lasting access to the account requires (the registration of a passkey
    /// for instance). The proof presented by the endpoint must match the session (a mismatch revokes it).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>The session, or the error and its resource name.</returns>
    public async ValueTask<(AuthCenterSession? Session, string? Error, string? ErrorId)> GetCriticalSessionAsync( IActivityMonitor monitor )
    {
        var (c, error, resName) = await GetCurrentAsync( monitor, revokeOnMismatch: true, acceptPrevious: false ).ConfigureAwait( false );
        if( c == null ) return (null, error, resName);
        if( _current.UnsafeActualActor.ActorId != c.Value.Session.ActualActorId )
        {
            return (null, "The authentication doesn't match the session.", "Authentication.InvalidSession");
        }
        if( _current.IsImpersonated )
        {
            return (null, "This is refused while impersonating.", "Authentication.Impersonated");
        }
        if( _current.ActualActor.Level != AuthLevel.Critical )
        {
            return (null, "This requires the Critical level.", "Authentication.CriticalLevelRequired");
        }
        return (c.Value.Session, null, null);
    }

    // Rotates the endpoint secrets (the current ones become the previous ones, unless the previous ones were presented:
    // they are then used), saves the session (with its actor and its end) and returns the new token.
    async ValueTask<ISessionResult> IssueAsync<T>( IActivityMonitor monitor, T command, Current c, int actorId, DateTime expires, AuthenticationInfo info, DateTime utcNow )
        where T : ICommand<ISessionResult>
    {
        var s = c.Session;
        var proof = _endpoint.Issue( s.SessionKey, s.RememberMe, expires );
        await c.Center.Sessions.SaveAsync( s.Rotate( proof.RefreshSecretHash, proof.BindingSecretHash, utcNow, c.FromPrevious ) with { ActorId = actorId, Expires = expires } )
                               .ConfigureAwait( false );
        return AuthCenterResults.Success( command, info, c.Center.CreateToken( s.SessionId, proof.BindingSecretHash, info, utcNow ), s.RememberMe );
    }

    /// <summary>
    /// Refreshes the current session: the actors are read again (a disabled actor cannot refresh), the levels are
    /// at most <see cref="AuthLevel.Normal"/> (the <see cref="AuthLevel.Critical"/> level requires a login), the session
    /// slides (it ends <see cref="AuthCenterOptions.SessionLifetime"/> after this refresh), the secrets rotate and a new
    /// token is issued.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <returns>The session result.</returns>
    public async ValueTask<ISessionResult> RefreshAsync( IActivityMonitor monitor, IRefreshSessionCommand command )
    {
        using var sessionLock = await LockAsync().ConfigureAwait( false );
        var (c, error, resName) = await GetCurrentAsync( monitor, revokeOnMismatch: true, acceptPrevious: true ).ConfigureAwait( false );
        if( c == null )
        {
            _endpoint.Clear();
            return AuthCenterResults.Failure( monitor, command, error!, resName! );
        }
        var s = c.Value.Session;
        var actual = await _actors.GetActorInfoAsync( monitor, s.ActualActorId ).ConfigureAwait( false );
        var actor = s.ActorId == s.ActualActorId
                        ? actual
                        : await _actors.GetActorInfoAsync( monitor, s.ActorId ).ConfigureAwait( false );
        if( actual == null || actor == null )
        {
            c.Value.Center.Sessions.TryDelete( monitor, s.ActualActorId, s.SessionId );
            _endpoint.Clear();
            return AuthCenterResults.Failure( monitor, command, "The actor cannot be used anymore.", "Authentication.InvalidActor" );
        }
        var utcNow = DateTime.UtcNow;
        // The session slides: it ends SessionLifetime after its last refresh.
        var expires = utcNow + c.Value.Center.Options.SessionLifetime;
        var info = AuthenticationInfo.Create( ToNormal( actual ), ToNormal( actor ), expires, null, s.DeviceId, utcNow );
        return await IssueAsync( monitor, command, c.Value, actor.ActorId, expires, info, utcNow ).ConfigureAwait( false );

        static ActorInfo ToNormal( ActorInfo a ) => a.Level > AuthLevel.Normal ? a.WithLevel( AuthLevel.Normal ) : a;
    }

    /// <summary>
    /// Ends the current session: it is deleted (when the proof matches) and the endpoint secrets are cleared.
    /// The session key is not a secret: a proof that doesn't match deletes nothing.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>The awaitable.</returns>
    public async ValueTask LogoutAsync( IActivityMonitor monitor )
    {
        using var sessionLock = await LockAsync().ConfigureAwait( false );
        var (c, _, _) = await GetCurrentAsync( monitor, revokeOnMismatch: false, acceptPrevious: true ).ConfigureAwait( false );
        if( c != null )
        {
            var s = c.Value.Session;
            c.Value.Center.Sessions.TryDelete( monitor, s.ActualActorId, s.SessionId );
            monitor.Info( $"Session of actor #{s.ActualActorId} ended." );
        }
        _endpoint.Clear();
    }

    /// <summary>
    /// Impersonates the actual actor into another actor. The current authentication must be at the
    /// <see cref="AuthLevel.Critical"/> level (also required by <see cref="ICommandAuthCritical"/>) and the optional
    /// <see cref="IImpersonationService"/> must allow it: by default, any impersonation is refused.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <returns>The session result.</returns>
    public async ValueTask<ISessionResult> ImpersonateAsync( IActivityMonitor monitor, IImpersonateCommand command )
    {
        if( command.TargetActorId.HasValue == (command.TargetActorName != null) )
        {
            return AuthCenterResults.Failure( monitor, command, "Exactly one of TargetActorId or TargetActorName must be set.", "Authentication.InvalidImpersonation" );
        }
        using var sessionLock = await LockAsync().ConfigureAwait( false );
        var (c, error, resName) = await GetCurrentAsync( monitor, revokeOnMismatch: true, acceptPrevious: true ).ConfigureAwait( false );
        if( c == null ) return AuthCenterResults.Failure( monitor, command, error!, resName! );
        var actual = _current.UnsafeActualActor;
        if( actual.ActorId != c.Value.Session.ActualActorId || _current.ActualActor.Level != AuthLevel.Critical )
        {
            return AuthCenterResults.Failure( monitor, command, "Impersonation requires the Critical level.", "Authentication.CriticalLevelRequired" );
        }
        if( command.TargetActorId == actual.ActorId
            || (command.TargetActorName != null && string.Equals( command.TargetActorName, actual.ActorName, StringComparison.OrdinalIgnoreCase )) )
        {
            return AuthCenterResults.Failure( monitor, command, "Impersonating oneself: use the IClearImpersonationCommand.", "Authentication.InvalidImpersonation" );
        }
        var service = _services.GetService<IImpersonationService>();
        var target = service == null
                        ? null
                        : command.TargetActorId.HasValue
                            ? await service.ImpersonateAsync( monitor, _current, command.TargetActorId.Value ).ConfigureAwait( false )
                            : await service.ImpersonateAsync( monitor, _current, command.TargetActorName! ).ConfigureAwait( false );
        if( target == null )
        {
            return AuthCenterResults.Failure( monitor, command, "Impersonation is not allowed.", "Authentication.ImpersonationNotAllowed" );
        }
        var utcNow = DateTime.UtcNow;
        var info = AuthenticationInfo.Create( actual, c.Value.Session.Expires, _current.CriticalExpires, c.Value.Session.DeviceId, utcNow )
                                     .Impersonate( target, utcNow );
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"{actual} impersonates {target}." );
        return await IssueAsync( monitor, command, c.Value, target.ActorId, c.Value.Session.Expires, info, utcNow ).ConfigureAwait( false );
    }

    /// <summary>
    /// Ends the impersonation if any: the actual actor becomes the actor again. This is always possible since it
    /// can only lower the privileges.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <returns>The session result.</returns>
    public async ValueTask<ISessionResult> ClearImpersonationAsync( IActivityMonitor monitor, IClearImpersonationCommand command )
    {
        using var sessionLock = await LockAsync().ConfigureAwait( false );
        var (c, error, resName) = await GetCurrentAsync( monitor, revokeOnMismatch: true, acceptPrevious: true ).ConfigureAwait( false );
        if( c == null ) return AuthCenterResults.Failure( monitor, command, error!, resName! );
        var actual = _current.UnsafeActualActor;
        if( actual.ActorId != c.Value.Session.ActualActorId )
        {
            return AuthCenterResults.Failure( monitor, command, "The authentication doesn't match the session.", "Authentication.InvalidSession" );
        }
        var utcNow = DateTime.UtcNow;
        var info = AuthenticationInfo.Create( actual, c.Value.Session.Expires, _current.CriticalExpires, c.Value.Session.DeviceId, utcNow );
        return await IssueAsync( monitor, command, c.Value, actual.ActorId, c.Value.Session.Expires, info, utcNow ).ConfigureAwait( false );
    }
}
