using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Handles the OpenID Connect logins of a local Authentication Center (see <see cref="AuthCenterOidc"/>):
/// the <see cref="IStartLoginCommand"/> of an "Oidc.&lt;Suffix&gt;" scheme and the <see cref="IRemoteLoginCallbackCommand"/>.
/// <para>
/// The login uses the "Oidc" <see cref="ILoginProvider"/>: its payload must have the writable string properties
/// <c>SchemeSuffix</c> and <c>Sub</c> (the payload of CK.DB.User.UserOidc for instance). A login succeeds only for an actor
/// already bound to (scheme, sub): there is no automatic account creation or binding (unless the application registers an
/// <see cref="IAutoCreateAccountService"/>).
/// </para>
/// </summary>
public sealed class AuthCenterOidcHandlers : ISingletonAutoService
{
    /// <summary>
    /// Validates an <see cref="IStartLoginCommand"/> of an OpenID Connect scheme: the scheme is configured, the
    /// endpoint can receive remote logins with an allowed callback, the return URL is relative.
    /// </summary>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IStartLoginCommand command, CurrentLocalParty localParty, IAuthenticationSessionEndpoint endpoint )
    {
        var center = localParty.LocalParty.GetFeature<CrisAuthCenter>()?.Local;
        var scheme = center?.Options.FindOidcScheme( command.Scheme );
        if( scheme == null )
        {
            c.Error( $"Unknown login scheme '{command.Scheme}'.", "Authentication.UnknownScheme" );
            return;
        }
        var callback = endpoint.RemoteLoginCallbackUrl;
        if( callback == null )
        {
            c.Error( "This endpoint cannot receive remote logins.", "Authentication.NoRemoteLogin" );
        }
        else if( !scheme.CallbackUrls.Contains( callback, StringComparer.Ordinal ) )
        {
            c.Error( $"The callback '{callback}' is not allowed for the scheme '{scheme.Scheme}'.", "Authentication.CallbackNotAllowed" );
        }
        if( command.ReturnUrl != null && !IsRelativeUrl( command.ReturnUrl ) )
        {
            c.Error( "The return URL must be a relative path.", "Authentication.InvalidReturnUrl" );
        }
    }

    /// <summary>
    /// Starts an OpenID Connect login.
    /// </summary>
    [CommandHandler]
    public async Task<RedirectedUrl> HandleAsync( IActivityMonitor monitor, IStartLoginCommand command, CurrentLocalParty localParty, IAuthenticationSessionEndpoint endpoint )
    {
        // The validator has checked the scheme and the callback.
        var center = localParty.LocalParty.GetRequiredFeature<CrisAuthCenter>().Local!;
        var scheme = center.Options.FindOidcScheme( command.Scheme )!;
        var (url, error) = await center.Oidc.StartAsync( monitor,
                                                         scheme,
                                                         endpoint.RemoteLoginCallbackUrl!,
                                                         endpoint.PrepareRemoteLogin(),
                                                         command.RememberMe,
                                                         DateTime.UtcNow ).ConfigureAwait( false );
        if( url == null ) Throw.CKException( error! );
        return new RedirectedUrl( url, command.InlineMode );
    }

    /// <summary>
    /// Completes an OpenID Connect login.
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
        var completion = await center.Oidc.CompleteAsync( monitor,
                                                          command.State,
                                                          command.Code,
                                                          command.Error,
                                                          endpoint.PresentedRemoteLoginHash,
                                                          DateTime.UtcNow ).ConfigureAwait( false );
        if( !completion.Success )
        {
            return AuthCenterResults.Failure( monitor, command, completion.Error!, completion.ErrorId! );
        }
        var scheme = completion.Scheme!;
        var provider = providers.FirstOrDefault( p => p.ProviderNames.Contains( "Oidc", StringComparer.OrdinalIgnoreCase ) );
        if( provider == null )
        {
            return AuthCenterResults.Failure( monitor, command, "There is no 'Oidc' login provider.", "Authentication.UnknownScheme" );
        }
        var payload = provider.CreatePayload( scheme.Scheme );
        if( !TrySet( payload, "SchemeSuffix", scheme.Suffix ) || !TrySet( payload, "Sub", completion.Sub! ) )
        {
            return AuthCenterResults.Failure( monitor, command, $"The payload of the 'Oidc' login provider ('{payload.GetType():N}') has no writable SchemeSuffix and Sub.", "Authentication.InvalidPayload" );
        }
        return await opener.OpenSessionAsync( monitor, command, scheme.Scheme, payload, completion.RememberMe ).ConfigureAwait( false );
    }

    static bool TrySet( object payload, string name, string value )
    {
        var p = payload.GetType().GetProperty( name, BindingFlags.Public | BindingFlags.Instance );
        if( p == null || p.PropertyType != typeof( string ) || !p.CanWrite ) return false;
        p.SetValue( payload, value );
        return true;
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
