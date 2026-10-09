using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
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
/// Handles the generic remote login commands of a local Authentication Center: the <see cref="IStartLoginCommand"/> and
/// the <see cref="IRemoteLoginCallbackCommand"/>. The scheme is resolved to its <see cref="IAuthCenterRemoteScheme"/> family,
/// that runs its protocol; the pending logins are kept here (<see cref="LocalAuthCenter.PendingRemoteLogins"/>): their state,
/// their correlation with the browser that started them, their expiry and their user data.
/// </summary>
public sealed class AuthCenterRemoteLoginHandlers : ISingletonAutoService
{
    /// <summary>
    /// Validates an <see cref="IStartLoginCommand"/>: the scheme belongs to a remote family, the endpoint can receive
    /// remote logins with an allowed callback, the return URL is relative.
    /// </summary>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IStartLoginCommand command, CurrentLocalParty localParty, IAuthenticationSessionEndpoint endpoint )
    {
        var center = localParty.LocalParty.GetFeature<CrisAuthCenter>()?.Local;
        if( center?.FindSchemeFamily( command.Scheme ) is not IAuthCenterRemoteScheme family )
        {
            c.Error( $"Unknown login scheme '{command.Scheme}'.", "Authentication.UnknownScheme" );
            return;
        }
        var callback = endpoint.RemoteLoginCallbackUrl;
        if( callback == null )
        {
            c.Error( "This endpoint cannot receive remote logins.", "Authentication.NoRemoteLogin" );
        }
        else if( !family.IsAllowedCallback( command.Scheme, callback ) )
        {
            c.Error( $"The callback '{callback}' is not allowed for the scheme '{command.Scheme}'.", "Authentication.CallbackNotAllowed" );
        }
        if( command.ReturnUrl != null && !IsRelativeUrl( command.ReturnUrl ) )
        {
            c.Error( "The return URL must be a relative path.", "Authentication.InvalidReturnUrl" );
        }
    }

    /// <summary>
    /// Starts a remote login.
    /// </summary>
    [CommandHandler]
    public async Task<RedirectedUrl> HandleAsync( IActivityMonitor monitor, IStartLoginCommand command, CurrentLocalParty localParty, IAuthenticationSessionEndpoint endpoint )
    {
        // The validator has checked the scheme and the callback.
        var center = localParty.LocalParty.GetRequiredFeature<CrisAuthCenter>().Local!;
        var family = (IAuthCenterRemoteScheme)center.FindSchemeFamily( command.Scheme )!;
        var callbackUrl = endpoint.RemoteLoginCallbackUrl!;
        var pendings = center.PendingRemoteLogins;
        if( !pendings.HasRoom( DateTime.UtcNow ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Too many pending logins ({pendings.Count}): '{command.Scheme}' login refused." );
            Throw.CKException( "Too many logins in progress. Please retry later." );
        }
        var state = Base64Url.EncodeToString( RandomNumberGenerator.GetBytes( 32 ) );
        var start = await family.StartAsync( monitor, command.Scheme, state, callbackUrl ).ConfigureAwait( false );
        if( start.Url == null ) Throw.CKException( start.Error ?? $"The '{command.Scheme}' login cannot start." );
        var userData = command.UserData.Count == 0
                        ? ImmutableDictionary<string, string?>.Empty
                        : command.UserData.ToImmutableDictionary( kv => kv.Key, kv => (string?)kv.Value );
        var pending = new PendingRemoteLogin( family, command.Scheme, callbackUrl, endpoint.PrepareRemoteLogin(), command.RememberMe, userData, start.SchemeData );
        if( !pendings.TryAdd( state, pending, DateTime.UtcNow ) )
        {
            Throw.CKException( "Too many logins in progress. Please retry later." );
        }
        return new RedirectedUrl( start.Url, command.InlineMode );
    }

    /// <summary>
    /// Completes a remote login: the pending login is consumed (one use), its expiry and its correlation with the browser
    /// are checked, its family completes it and the session is opened with the user data of its start.
    /// </summary>
    [CommandHandler]
    public async ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor,
                                                        IRemoteLoginCallbackCommand command,
                                                        CurrentLocalParty localParty,
                                                        IAuthenticationSessionEndpoint endpoint,
                                                        IAuthenticationSessionOpener opener,
                                                        IEnumerable<ILoginProvider> providers )
    {
        var center = localParty.LocalParty.GetFeature<CrisAuthCenter>()?.Local;
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
        var presented = endpoint.PresentedRemoteLoginHash;
        if( presented == null
            || !CryptographicOperations.FixedTimeEquals( Encoding.ASCII.GetBytes( presented ), Encoding.ASCII.GetBytes( pending.CorrelationHash ) ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{pending.Scheme}' login completed by a caller that didn't start it." );
            return AuthCenterResults.Failure( monitor, command, "This login has not been started here.", "Authentication.RemoteLoginCorrelation" );
        }
        var providerName = pending.Family.ProviderName;
        var provider = providers.FirstOrDefault( p => p.ProviderNames.Contains( providerName, StringComparer.OrdinalIgnoreCase ) );
        if( provider == null )
        {
            return AuthCenterResults.Failure( monitor, command, $"There is no '{providerName}' login provider.", "Authentication.UnknownScheme" );
        }
        var completion = await pending.Family.CompleteAsync( monitor, pending, command.Code, command.Error, provider ).ConfigureAwait( false );
        if( completion.Payload == null )
        {
            return AuthCenterResults.Failure( monitor, command, completion.Error ?? "Login failed.", completion.ErrorId ?? "Authentication.RemoteLoginFailed" );
        }
        return await opener.OpenSessionAsync( monitor, command, pending.Scheme, completion.Payload, pending.RememberMe, pending.UserData ).ConfigureAwait( false );
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
