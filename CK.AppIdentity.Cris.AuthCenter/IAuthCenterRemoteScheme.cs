using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// A family of remote login schemes (OpenID Connect...): the user logs in at a provider that sends the browser back
/// to the callback of the endpoint.
/// <para>
/// The core handles the generic <c>IStartLoginCommand</c> and <c>IRemoteLoginCallbackCommand</c>: it owns the pending
/// remote logins (the state, the correlation with the browser, the expiry, the user data) and dispatches to the family
/// of the scheme, that only runs its protocol.
/// </para>
/// </summary>
public interface IAuthCenterRemoteScheme : IAuthCenterScheme
{
    /// <summary>
    /// Gets whether the callback URL of an endpoint is allowed for a scheme.
    /// </summary>
    /// <param name="scheme">One of the <see cref="IAuthCenterScheme.Schemes"/>.</param>
    /// <param name="callbackUrl">The callback URL of the endpoint.</param>
    /// <returns>True if the provider can send the browser back to this URL.</returns>
    bool IsAllowedCallback( string scheme, string callbackUrl );

    /// <summary>
    /// Prepares a login: returns the URL to navigate to, and the private data of the family that the core keeps with the
    /// pending login (it is given back to <see cref="CompleteAsync"/>).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="scheme">One of the <see cref="IAuthCenterScheme.Schemes"/>.</param>
    /// <param name="state">The state of the login, chosen by the core: the provider must send it back.</param>
    /// <param name="callbackUrl">The (allowed) callback URL of the endpoint.</param>
    /// <returns>The URL and the private data, or the error.</returns>
    Task<RemoteLoginStart> StartAsync( IActivityMonitor monitor, string scheme, string state, string callbackUrl );

    /// <summary>
    /// Completes a pending login of this family: the core has already consumed it (one use) and checked its expiry and
    /// its correlation with the browser.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="pending">The pending login.</param>
    /// <param name="code">The code sent back by the provider.</param>
    /// <param name="error">The error sent back by the provider, if any.</param>
    /// <param name="provider">The login provider of <see cref="IAuthCenterScheme.ProviderName"/>: the payload must be its own.</param>
    /// <returns>The payload of the provider, or the error.</returns>
    Task<RemoteLoginCompletion> CompleteAsync( IActivityMonitor monitor, PendingRemoteLogin pending, string? code, string? error, ILoginProvider provider );
}

/// <summary>
/// The result of <see cref="IAuthCenterRemoteScheme.StartAsync"/>.
/// </summary>
/// <param name="Url">The URL to navigate to. Null on error.</param>
/// <param name="SchemeData">The private data of the family, kept with the pending login.</param>
/// <param name="Error">The error text. Null on success.</param>
public readonly record struct RemoteLoginStart( string? Url, object? SchemeData, string? Error );

/// <summary>
/// The result of <see cref="IAuthCenterRemoteScheme.CompleteAsync"/>.
/// </summary>
/// <param name="Payload">The payload of the login provider. Null on error.</param>
/// <param name="Error">The error text. Null on success.</param>
/// <param name="ErrorId">The error resource name. Null on success.</param>
public readonly record struct RemoteLoginCompletion( object? Payload, string? Error, string? ErrorId )
{
    /// <summary>
    /// Creates a failure.
    /// </summary>
    /// <param name="error">The error text.</param>
    /// <param name="errorId">The error resource name.</param>
    /// <returns>The failure.</returns>
    public static RemoteLoginCompletion Failure( string error, string errorId ) => new( null, error, errorId );
}
