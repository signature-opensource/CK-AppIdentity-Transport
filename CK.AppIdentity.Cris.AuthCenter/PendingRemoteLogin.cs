using System.Collections.Generic;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// A remote login that has started and waits for its callback. The core of the Authentication Center keeps it (in
/// memory, one use, for <see cref="LocalAuthCenter.PendingRemoteLoginLifetime"/>) under its state.
/// </summary>
public sealed class PendingRemoteLogin
{
    internal PendingRemoteLogin( IAuthCenterRemoteScheme family,
                                 string scheme,
                                 string callbackUrl,
                                 string correlationHash,
                                 bool rememberMe,
                                 IReadOnlyDictionary<string, string?> userData,
                                 object? schemeData )
    {
        Family = family;
        Scheme = scheme;
        CallbackUrl = callbackUrl;
        CorrelationHash = correlationHash;
        RememberMe = rememberMe;
        UserData = userData;
        SchemeData = schemeData;
    }

    internal IAuthCenterRemoteScheme Family { get; }

    /// <summary>
    /// Gets the scheme of the login.
    /// </summary>
    public string Scheme { get; }

    /// <summary>
    /// Gets the callback URL of the endpoint that started the login.
    /// </summary>
    public string CallbackUrl { get; }

    /// <summary>
    /// Gets the hash of the correlation secret of the browser that started the login.
    /// </summary>
    public string CorrelationHash { get; }

    /// <summary>
    /// Gets whether the session must be remembered.
    /// </summary>
    public bool RememberMe { get; }

    /// <summary>
    /// Gets the user data of the start of the login (an immutable copy): the callback doesn't carry them.
    /// </summary>
    public IReadOnlyDictionary<string, string?> UserData { get; }

    /// <summary>
    /// Gets the private data of the family (see <see cref="RemoteLoginStart.SchemeData"/>).
    /// </summary>
    public object? SchemeData { get; }
}
