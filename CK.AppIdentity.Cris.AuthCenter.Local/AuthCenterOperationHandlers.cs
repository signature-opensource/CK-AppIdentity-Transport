using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The handlers of the internal session operations (the <c>[Internal]</c> commands of CK.IO.Authentication) on a local
/// Authentication Center. The session commands are executed by the endpoint that received them (CK.Cris.Authentication),
/// which executes these operations: locally here when the endpoint is the Authentication Center, dispatched to it from
/// any other party. An operation is handled with an <see cref="OperationSessionEndpoint"/> built from its data, so the
/// logic is the same wherever it comes from; its result tells the receiving endpoint what to issue or clear.
/// </summary>
public sealed class AuthCenterOperationHandlers : ISingletonAutoService
{
    /// <summary>
    /// Creates the session service of an operation.
    /// </summary>
    /// <param name="services">The services of the operation's scope.</param>
    /// <param name="endpoint">The endpoint of the operation.</param>
    /// <returns>The session service.</returns>
    public static AuthCenterSessionService CreateSessionService( IServiceProvider services, IAuthenticationSessionEndpoint endpoint )
    {
        return new AuthCenterSessionService( services.GetRequiredService<CurrentLocalParty>(),
                                             services.GetRequiredService<AuthenticationInfo>(),
                                             endpoint,
                                             services.GetRequiredService<IActorInfoProvider>(),
                                             services );
    }

    /// <summary>
    /// Creates the session issuer of an operation.
    /// </summary>
    /// <param name="services">The services of the operation's scope.</param>
    /// <param name="endpoint">The endpoint of the operation.</param>
    /// <returns>The session issuer.</returns>
    public static AuthCenterSessionIssuer CreateIssuer( IServiceProvider services, IAuthenticationSessionEndpoint endpoint )
    {
        return new AuthCenterSessionIssuer( services.GetRequiredService<CurrentLocalParty>(),
                                            services.GetRequiredService<AuthenticationInfo>(),
                                            endpoint,
                                            services.GetServices<ILoginProvider>(),
                                            services.GetServices<ILoginValidator>(),
                                            services );
    }

    /// <summary>
    /// Opens a session (a login): the payload is the login command.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor, IOpenSessionOperationCommand op, IServiceProvider services, PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        if( op.Payload is not ICrisPoco login )
        {
            return endpoint.ToResult( pocos, AuthCenterResults.Failure( monitor, op, "The login operation has no payload.", "Authentication.InvalidCommand" ) );
        }
        var userData = op.UserData.Count > 0 ? op.UserData.ToImmutableDictionary( kv => kv.Key, kv => (string?)kv.Value ) : null;
        var r = await CreateIssuer( services, endpoint ).OpenSessionAsync( monitor, login, op.Scheme, login, op.RememberMe, userData ).ConfigureAwait( false );
        return endpoint.ToResult( pocos, r );
    }

    /// <summary>
    /// Refreshes the presented session.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor, IRefreshSessionOperationCommand op, IServiceProvider services, PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        var r = await CreateSessionService( services, endpoint ).RefreshAsync( monitor, op ).ConfigureAwait( false );
        return endpoint.ToResult( pocos, r );
    }

    /// <summary>
    /// Ends the presented session.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor, ILogoutSessionOperationCommand op, IServiceProvider services, PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        await CreateSessionService( services, endpoint ).LogoutAsync( monitor ).ConfigureAwait( false );
        return endpoint.ToResult( pocos, null );
    }

    /// <summary>
    /// Impersonates in the presented session.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor, IImpersonateOperationCommand op, IServiceProvider services, PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        var r = await CreateSessionService( services, endpoint ).ImpersonateAsync( monitor, op, op.TargetActorId, op.TargetActorName ).ConfigureAwait( false );
        return endpoint.ToResult( pocos, r );
    }

    /// <summary>
    /// Clears the impersonation of the presented session.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor, IClearImpersonationOperationCommand op, IServiceProvider services, PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        var r = await CreateSessionService( services, endpoint ).ClearImpersonationAsync( monitor, op ).ConfigureAwait( false );
        return endpoint.ToResult( pocos, r );
    }

    /// <summary>
    /// Validates the start of a remote login: the scheme belongs to a remote family, the receiving endpoint's callback is
    /// allowed for it, the return URL is relative.
    /// </summary>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IStartRemoteLoginOperationCommand op, CurrentLocalParty localParty )
    {
        var login = op.Login;
        if( login == null )
        {
            c.Error( "The remote login operation has no start command.", "Authentication.InvalidCommand" );
            return;
        }
        var center = localParty.LocalParty.GetFeature<LocalAuthCenter>();
        if( center?.FindSchemeFamily( login.Scheme ) is not IAuthCenterRemoteScheme family )
        {
            c.Error( $"Unknown login scheme '{login.Scheme}'.", "Authentication.UnknownScheme" );
            return;
        }
        if( string.IsNullOrEmpty( op.CallbackUrl ) )
        {
            c.Error( "This endpoint cannot receive remote logins.", "Authentication.NoRemoteLogin" );
        }
        else if( !family.IsAllowedCallback( login.Scheme, op.CallbackUrl ) )
        {
            c.Error( $"The callback '{op.CallbackUrl}' is not allowed for the scheme '{login.Scheme}'.", "Authentication.CallbackNotAllowed" );
        }
        if( login.ReturnUrl != null && !IsRelativeUrl( login.ReturnUrl ) )
        {
            c.Error( "The return URL must be a relative path.", "Authentication.InvalidReturnUrl" );
        }
    }

    /// <summary>
    /// Starts a remote login: a pending login (one use, its correlation hash, its user data) and the provider URL.
    /// A binding (<see cref="IStartLoginCommand.BindToCurrentActor"/>) requires the presented session to be at the
    /// Critical level and not impersonated: the pending login carries this session and its authentication.
    /// </summary>
    [CommandHandler]
    public async Task<RedirectedUrl> HandleAsync( IActivityMonitor monitor,
                                                  IStartRemoteLoginOperationCommand op,
                                                  CurrentLocalParty localParty,
                                                  IServiceProvider services,
                                                  AuthenticationInfo authentication )
    {
        // The validator has checked the scheme and the callback.
        var login = op.Login!;
        var center = localParty.LocalParty.GetRequiredFeature<LocalAuthCenter>();
        var family = (IAuthCenterRemoteScheme)center.FindSchemeFamily( login.Scheme )!;
        string? bindingSessionKey = null;
        if( login.BindToCurrentActor )
        {
            var (session, error, _) = await CreateSessionService( services, new OperationSessionEndpoint( op ) ).GetCriticalSessionAsync( monitor )
                                                                                                                .ConfigureAwait( false );
            if( session == null ) Throw.CKException( error! );
            bindingSessionKey = session.SessionKey;
        }
        var pendings = center.PendingRemoteLogins;
        if( !pendings.HasRoom( DateTime.UtcNow ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Too many pending logins ({pendings.Count}): '{login.Scheme}' login refused." );
            Throw.CKException( "Too many logins in progress. Please retry later." );
        }
        var state = Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 32 ) );
        var start = await family.StartAsync( monitor, login.Scheme, state, op.CallbackUrl, login.Critical ).ConfigureAwait( false );
        if( start.Url == null ) Throw.CKException( start.Error ?? $"The '{login.Scheme}' login cannot start." );
        var userData = login.UserData.Count == 0
                        ? ImmutableDictionary<string, string?>.Empty
                        : login.UserData.ToImmutableDictionary( kv => kv.Key, kv => (string?)kv.Value );
        var pending = new PendingRemoteLogin( family,
                                              login.Scheme,
                                              op.CallbackUrl,
                                              op.CorrelationHash,
                                              login.RememberMe,
                                              userData,
                                              start.SchemeData,
                                              bindingSessionKey,
                                              bindingSessionKey != null ? authentication : null );
        if( !pendings.TryAdd( state, pending, DateTime.UtcNow ) )
        {
            Throw.CKException( "Too many logins in progress. Please retry later." );
        }
        return new RedirectedUrl( start.Url, login.InlineMode );
    }

    /// <summary>
    /// Completes a remote login: the pending login is consumed (one use), its expiry and its correlation with the caller
    /// that started it are checked, its family completes it and the session is opened with the user data of its start.
    /// A binding (<see cref="IStartLoginCommand.BindToCurrentActor"/>) binds the identity to the actor of the session that
    /// started it, through the <see cref="IAutoBindingAccountService"/>: its successful result issues no session.
    /// </summary>
    [CommandHandler]
    public async Task<ISessionOperationResult> HandleAsync( IActivityMonitor monitor,
                                                            ICompleteRemoteLoginOperationCommand op,
                                                            CurrentLocalParty localParty,
                                                            IServiceProvider services,
                                                            PocoDirectory pocos )
    {
        var endpoint = new OperationSessionEndpoint( op );
        return endpoint.ToResult( pocos, await CompleteAsync().ConfigureAwait( false ) );

        async Task<ISessionResult> CompleteAsync()
        {
            var command = op.Callback;
            if( command == null )
            {
                return AuthCenterResults.Failure( monitor, op, "The remote login operation has no callback.", "Authentication.InvalidCommand" );
            }
            var center = localParty.LocalParty.GetFeature<LocalAuthCenter>();
            if( center == null )
            {
                return AuthCenterResults.Failure( monitor, command, $"'{localParty.LocalParty}' is not an AuthCenter.", "Authentication.NoAuthCenter" );
            }
            var pending = center.PendingRemoteLogins.TryTake( command.State, DateTime.UtcNow, out bool expired );
            if( pending == null )
            {
                return expired
                        ? AuthCenterResults.Failure( monitor, command, "This login has expired.", "Authentication.RemoteLoginExpired" )
                        : AuthCenterResults.Failure( monitor, command, "This login is unknown or has expired.", "Authentication.RemoteLoginExpired" );
            }
            var presented = op.PresentedCorrelationHash;
            if( presented == null
                || !CryptographicOperations.FixedTimeEquals( Encoding.ASCII.GetBytes( presented ), Encoding.ASCII.GetBytes( pending.CorrelationHash ) ) )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{pending.Scheme}' login completed by a caller that didn't start it." );
                return AuthCenterResults.Failure( monitor, command, "This login has not been started here.", "Authentication.RemoteLoginCorrelation" );
            }
            var providerName = pending.Family.ProviderName;
            var provider = services.GetServices<ILoginProvider>().FirstOrDefault( p => p.ProviderNames.Contains( providerName, StringComparer.OrdinalIgnoreCase ) );
            if( provider == null )
            {
                return AuthCenterResults.Failure( monitor, command, $"There is no '{providerName}' login provider.", "Authentication.UnknownScheme" );
            }
            var completion = await pending.Family.CompleteAsync( monitor, pending, command.Code, command.Error, provider ).ConfigureAwait( false );
            if( completion.Payload == null )
            {
                return AuthCenterResults.Failure( monitor, command, completion.Error ?? "Login failed.", completion.ErrorId ?? "Authentication.RemoteLoginFailed" );
            }
            if( pending.BindingSessionKey != null )
            {
                return await BindAsync( monitor, command, center, pending, provider, completion.Payload, services, pocos ).ConfigureAwait( false );
            }
            return await CreateIssuer( services, endpoint ).OpenSessionAsync( monitor,
                                                                              command,
                                                                              pending.Scheme,
                                                                              completion.Payload,
                                                                              pending.RememberMe,
                                                                              pending.UserData,
                                                                              completion.AuthenticationTime )
                                                           .ConfigureAwait( false );
        }
    }

    // Binds the identity of a remote login to the actor that started it (IStartLoginCommand.BindToCurrentActor). The
    // session that started the binding must still be alive and not impersonated: the callback doesn't carry the session
    // cookies, the correlation (checked by the caller) proves the same browser. The Critical level was checked at the
    // start (the pending login lives at most PendingRemoteLoginLifetime). An identity already bound to the actor is
    // accepted, one bound to another actor is refused; no account is created and no session is issued.
    static async Task<ISessionResult> BindAsync( IActivityMonitor monitor,
                                                 ICrisPoco command,
                                                 LocalAuthCenter center,
                                                 PendingRemoteLogin pending,
                                                 ILoginProvider provider,
                                                 object payload,
                                                 IServiceProvider services,
                                                 PocoDirectory pocos )
    {
        var auth = pending.BindingAuthentication!;
        var actorId = auth.UnsafeActualActor.ActorId;
        var session = AuthCenterSession.TryParseSessionKey( pending.BindingSessionKey, out var actualActorId, out var sessionId )
                        ? await center.Sessions.TryReadAsync( monitor, actualActorId, sessionId ).ConfigureAwait( false )
                        : null;
        if( session == null
            || session.Expires <= DateTime.UtcNow
            || session.ActualActorId != actorId
            || session.ActorId != actorId )
        {
            return AuthCenterResults.Failure( monitor, command, "The session that started the binding has ended.", "Authentication.BindingSessionEnded" );
        }
        try
        {
            var r = await provider.LoginAsync( monitor, pending.Scheme, payload, actualLogin: false ).ConfigureAwait( false );
            if( r.IsSuccess )
            {
                if( r.Actor!.ActorId != actorId )
                {
                    monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"User #{actorId} cannot bind a '{pending.Scheme}' identity that is bound to another user." );
                    return AuthCenterResults.Failure( monitor, command, "This identity is already used by another account.", "Authentication.IdentityBoundToAnotherUser" );
                }
                return Bound( pocos, "This identity is already bound to your account.", "Authentication.IdentityAlreadyBound" );
            }
            if( !r.IsUnregisteredUser )
            {
                return AuthCenterResults.Failure( monitor, command, r.FailureReason ?? "Login failed.", "Authentication.LoginFailed" );
            }
            var binder = services.GetService<IAutoBindingAccountService>();
            if( binder == null )
            {
                return AuthCenterResults.Failure( monitor, command, "This application doesn't bind identities.", "Authentication.BindingNotAvailable" );
            }
            var context = new LoginContext( pending.Scheme, payload, auth, pending.UserData );
            var b = await binder.BindAccountAsync( monitor, context ).ConfigureAwait( false );
            if( context.HasError )
            {
                return AuthCenterResults.Failure( monitor, command, context.ErrorText ?? context.ErrorId!, context.ErrorId! );
            }
            if( b == null || !b.IsSuccess || b.Actor!.ActorId != actorId )
            {
                return AuthCenterResults.Failure( monitor, command, b?.FailureReason ?? "The identity cannot be bound.", "Authentication.BindingFailed" );
            }
        }
        catch( Exception ex )
        {
            monitor.Error( $"While binding a '{pending.Scheme}' identity to user #{actorId}.", ex );
            return AuthCenterResults.Failure( monitor, command, "The identity cannot be bound.", "Authentication.BindingFailed" );
        }
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"User #{actorId} bound a '{pending.Scheme}' identity." );
        return Bound( pocos, "The identity is bound to your account.", "Authentication.IdentityBound" );

        static ISessionResult Bound( PocoDirectory pocos, string text, string resName )
        {
            return pocos.Create<ISessionResult>( r =>
            {
                r.Success = true;
                r.UserMessages.Add( UserMessage.Info( NormalizedCultureInfo.CodeDefault, text, resName ) );
            } );
        }
    }

    /// <summary>
    /// Gets whether a URL is a relative path of this origin: it starts with a single '/' (not "//" nor "/\") and has no
    /// backslash nor control character.
    /// </summary>
    /// <param name="url">The url.</param>
    /// <returns>True if it is a relative path.</returns>
    public static bool IsRelativeUrl( string url )
    {
        if( url.Length == 0 || url[0] != '/' ) return false;
        if( url.Length > 1 && (url[1] == '/' || url[1] == '\\') ) return false;
        return !url.Any( ch => ch == '\\' || char.IsControl( ch ) );
    }
}
