using CK.Auth;
using CK.Core;
using CK.IO.Authentication;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The session endpoint of an internal session operation, built from its data: it presents what the receiving endpoint
/// presented (<see cref="ICommandPresentedSession"/>), its secrets are the ones that endpoint prepared
/// (<see cref="ICommandNextSessionSecrets"/>), and it records what the receiving endpoint must apply: the result of the
/// operation (<see cref="ToResult"/>). The Authentication Center's logic works with it as with any endpoint, wherever the
/// operation comes from (the local endpoint or a remote).
/// </summary>
public sealed class OperationSessionEndpoint : IAuthenticationSessionEndpoint
{
    readonly ICommandPresentedSession? _presented;
    readonly ICommandNextSessionSecrets? _next;
    readonly string? _correlationHash;

    /// <summary>
    /// Initializes a new operation endpoint.
    /// </summary>
    /// <param name="operation">The operation: its <see cref="ICommandPresentedSession"/> and <see cref="ICommandNextSessionSecrets"/> parts are used.</param>
    /// <param name="remoteLoginCallbackUrl">The callback URL of the receiving endpoint (a starting remote login).</param>
    /// <param name="remoteLoginCorrelationHash">The correlation hash prepared by the receiving endpoint (a starting remote login).</param>
    /// <param name="presentedRemoteLoginHash">The correlation hash presented to the receiving endpoint (a completing remote login).</param>
    /// <param name="webOrigin">The web origin checked by the receiving endpoint.</param>
    public OperationSessionEndpoint( object operation,
                                     string? remoteLoginCallbackUrl = null,
                                     string? remoteLoginCorrelationHash = null,
                                     string? presentedRemoteLoginHash = null,
                                     string? webOrigin = null )
    {
        Throw.CheckNotNullArgument( operation );
        _presented = operation as ICommandPresentedSession;
        _next = operation as ICommandNextSessionSecrets;
        RemoteLoginCallbackUrl = remoteLoginCallbackUrl;
        _correlationHash = remoteLoginCorrelationHash;
        PresentedRemoteLoginHash = presentedRemoteLoginHash;
        WebOrigin = webOrigin;
    }

    /// <inheritdoc />
    public AuthenticationSessionProof? PresentedProof => _presented?.PresentedSessionKey == null
                                                            ? null
                                                            : new AuthenticationSessionProof( _presented.PresentedSessionKey,
                                                                                              _presented.PresentedRefreshSecretHash ?? string.Empty,
                                                                                              _presented.PresentedBindingSecretHash ?? string.Empty );

    /// <summary>
    /// Always null: the token was read by the receiving endpoint (and, across parties, by the identity bridge).
    /// </summary>
    public string? PresentedToken => null;

    /// <inheritdoc />
    public (string RefreshSecretHash, string BindingSecretHash) PrepareSecrets()
    {
        if( _next == null ) Throw.InvalidOperationException( "This operation carries no prepared secrets." );
        return (_next.NextRefreshSecretHash, _next.NextBindingSecretHash);
    }

    /// <summary>
    /// Gets the key of the session to issue. Null when no session is issued.
    /// </summary>
    public string? IssuedSessionKey { get; private set; }

    /// <summary>
    /// Gets whether the issued session survives the end of the caller session.
    /// </summary>
    public bool RememberMe { get; private set; }

    /// <summary>
    /// Gets the expiration of the issued session's refresh secret.
    /// </summary>
    public DateTime RefreshExpires { get; private set; }

    /// <summary>
    /// Gets whether the receiving endpoint must clear its secrets.
    /// </summary>
    public bool Cleared { get; private set; }

    /// <inheritdoc />
    public AuthenticationSessionProof Issue( string sessionKey, bool rememberMe, DateTime refreshExpires )
    {
        var (refresh, binding) = PrepareSecrets();
        IssuedSessionKey = sessionKey;
        RememberMe = rememberMe;
        RefreshExpires = refreshExpires;
        Cleared = false;
        return new AuthenticationSessionProof( sessionKey, refresh, binding );
    }

    /// <inheritdoc />
    public void Clear()
    {
        IssuedSessionKey = null;
        Cleared = true;
    }

    /// <inheritdoc />
    public string? RemoteLoginCallbackUrl { get; }

    /// <inheritdoc />
    public string PrepareRemoteLogin() => _correlationHash
                                          ?? Throw.InvalidOperationException<string>( "The receiving endpoint did not prepare the remote login correlation." );

    /// <inheritdoc />
    public string? PresentedRemoteLoginHash { get; }

    /// <inheritdoc />
    public string? WebOrigin { get; }

    /// <summary>
    /// Creates the result of the operation: what the receiving endpoint applies.
    /// </summary>
    /// <param name="pocos">The poco directory.</param>
    /// <param name="result">The session result (null for an operation without result, the logout).</param>
    /// <returns>The operation result.</returns>
    public ISessionOperationResult ToResult( PocoDirectory pocos, ISessionResult? result )
    {
        return pocos.Create<ISessionOperationResult>( r =>
        {
            r.Result = result;
            r.IssuedSessionKey = IssuedSessionKey;
            r.RememberMe = RememberMe;
            r.RefreshExpires = RefreshExpires;
            r.Cleared = Cleared;
        } );
    }
}
