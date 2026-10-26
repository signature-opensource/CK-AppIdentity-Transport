using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Buffers.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Implements the <see cref="IAuthenticationSessionOpener"/> of a local Authentication Center: the
/// <see cref="CurrentLocalParty"/> must have its <see cref="LocalAuthCenter"/>.
/// <para>
/// The login sequence is: the <see cref="ILoginProvider"/> of the scheme (only a check when there are
/// <see cref="ILoginValidator"/>), the validators, the actual login. An unregistered user can be created
/// (<see cref="IAutoCreateAccountService"/>, nobody is logged in, only for a scheme whose <see cref="IAuthCenterScheme"/>
/// family allows it: <see cref="IAuthCenterScheme.AllowsAccountCreation"/>) or bound (<see cref="IAutoBindingAccountService"/>,
/// somebody is logged in). On success, the session is stored, the endpoint issues its secrets and the result carries
/// the signed token.
/// </para>
/// </summary>
public sealed class AuthCenterSessionOpener : IAuthenticationSessionOpener
{
    readonly CurrentLocalParty _localParty;
    readonly AuthenticationInfo _initial;
    readonly IAuthenticationSessionEndpoint _endpoint;
    readonly IEnumerable<ILoginProvider> _providers;
    readonly IEnumerable<ILoginValidator> _validators;
    readonly IServiceProvider _services;

    /// <summary>
    /// Initializes a new session opener.
    /// </summary>
    /// <param name="localParty">The current local party: its Authentication Center must be local.</param>
    /// <param name="initial">The authentication before the login.</param>
    /// <param name="endpoint">The endpoint that received the command.</param>
    /// <param name="providers">The login providers.</param>
    /// <param name="validators">The login validators.</param>
    /// <param name="services">The services, for the optional account creation and binding services.</param>
    public AuthCenterSessionOpener( CurrentLocalParty localParty,
                                    AuthenticationInfo initial,
                                    IAuthenticationSessionEndpoint endpoint,
                                    IEnumerable<ILoginProvider> providers,
                                    IEnumerable<ILoginValidator> validators,
                                    IServiceProvider services )
    {
        _localParty = localParty;
        _initial = initial;
        _endpoint = endpoint;
        _providers = providers;
        _validators = validators;
        _services = services;
    }

    /// <inheritdoc />
    public async ValueTask<ISessionResult> OpenSessionAsync<T>( IActivityMonitor monitor,
                                                                T command,
                                                                string scheme,
                                                                object payload,
                                                                bool rememberMe = false,
                                                                IReadOnlyDictionary<string, string?>? userData = null )
        where T : ICommand<ISessionResult>, ICommandAuthenticationSession
    {
        Throw.CheckNotNullArgument( command );
        Throw.CheckNotNullOrWhiteSpaceArgument( scheme );
        Throw.CheckNotNullArgument( payload );

        var center = _localParty.LocalParty.GetFeature<LocalAuthCenter>();
        if( center == null )
        {
            return Failure( monitor, command, $"'{_localParty.LocalParty}' has no AuthCenter.", "Authentication.NoAuthCenter" );
        }
        var providerName = LoginScheme.GetProviderName( scheme );
        var provider = _providers.FirstOrDefault( p => p.ProviderNames.Contains( providerName, StringComparer.OrdinalIgnoreCase ) );
        if( provider == null )
        {
            return Failure( monitor, command, $"Unknown login scheme '{scheme}'.", "Authentication.UnknownScheme" );
        }

        // The user data of the command, unless the caller gives them (the remote login callback: the data of its start).
        userData ??= command is ICommandLoginUserData d && d.UserData.Count > 0
                        ? d.UserData.ToImmutableDictionary( kv => kv.Key, kv => (string?)kv.Value )
                        : null;
        var context = new LoginContext( scheme, payload, _initial, userData );
        // An account can be created only for a scheme whose family allows it (fail closed: Basic and Weak never do).
        bool allowsAccountCreation = center.FindSchemeFamily( scheme )?.AllowsAccountCreation( scheme ) is true;
        var r = await LoginAsync( monitor, provider, context, allowsAccountCreation ).ConfigureAwait( false );
        if( context.HasError )
        {
            return Failure( monitor, command, context.ErrorText ?? context.ErrorId!, context.ErrorId! );
        }
        if( r == null || !r.IsSuccess )
        {
            return Failure( monitor, command, r?.FailureReason ?? "Login failed.", "Authentication.LoginFailed" );
        }
        return await OpenAsync( monitor, command, center, r.Actor!, rememberMe ).ConfigureAwait( false );
    }

    async ValueTask<ActorLoginResult?> LoginAsync( IActivityMonitor monitor, ILoginProvider provider, LoginContext context, bool allowsAccountCreation )
    {
        ActorLoginResult r;
        if( _validators.Any() )
        {
            r = await provider.LoginAsync( monitor, context.Scheme, context.Payload, actualLogin: false ).ConfigureAwait( false );
            if( r.IsSuccess )
            {
                foreach( var v in _validators )
                {
                    await v.ValidateLoginAsync( monitor, r.Actor!, context ).ConfigureAwait( false );
                    if( context.HasError ) return null;
                }
                r = await provider.LoginAsync( monitor, context.Scheme, context.Payload, actualLogin: true ).ConfigureAwait( false );
            }
        }
        else
        {
            r = await provider.LoginAsync( monitor, context.Scheme, context.Payload, actualLogin: true ).ConfigureAwait( false );
        }
        if( r.IsSuccess || !r.IsUnregisteredUser ) return r;
        // An unregistered user: created when nobody is logged in (and the scheme allows it), bound to the current one otherwise.
        ActorLoginResult? fixedResult = _initial.UnsafeActualActor.IsAnonymous
                                        ? allowsAccountCreation
                                            ? await (_services.GetService<IAutoCreateAccountService>()?.CreateAccountAndLoginAsync( monitor, context ) ?? default).ConfigureAwait( false )
                                            : null
                                        : await (_services.GetService<IAutoBindingAccountService>()?.BindAccountAsync( monitor, context ) ?? default).ConfigureAwait( false );
        return fixedResult ?? r;
    }

    async ValueTask<ISessionResult> OpenAsync<T>( IActivityMonitor monitor, T command, LocalAuthCenter center, ActorInfo actor, bool rememberMe )
        where T : ICommand<ISessionResult>
    {
        var options = center.Options;
        var utcNow = DateTime.UtcNow;
        var expires = utcNow + options.SessionLifetime;
        DateTime? criticalExpires = actor.Level == AuthLevel.Critical ? utcNow + options.CriticalLifetime : null;
        var deviceId = _initial.DeviceId.Length > 0 ? _initial.DeviceId : Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 16 ) );
        var info = AuthenticationInfo.Create( actor, expires, criticalExpires, deviceId, utcNow );

        var sessionId = AuthCenterSession.NewSessionId();
        var proof = _endpoint.Issue( AuthCenterSession.GetSessionKey( actor.ActorId, sessionId ), rememberMe, expires );
        await center.Sessions.SaveAsync( new AuthCenterSession( sessionId,
                                                                actor.ActorId,
                                                                actor.ActorId,
                                                                utcNow,
                                                                expires,
                                                                rememberMe,
                                                                deviceId,
                                                                proof.RefreshSecretHash,
                                                                proof.BindingSecretHash ) ).ConfigureAwait( false );
        var token = center.CreateToken( sessionId, proof.BindingSecretHash, info, utcNow );
        monitor.Info( $"Session opened for {actor} in '{center.Party}'." );
        return AuthCenterResults.Success( command, info, token, rememberMe );
    }

    static ISessionResult Failure<T>( IActivityMonitor monitor, T command, string text, string resName ) where T : ICommand<ISessionResult>
        => AuthCenterResults.Failure( monitor, command, text, resName );
}
