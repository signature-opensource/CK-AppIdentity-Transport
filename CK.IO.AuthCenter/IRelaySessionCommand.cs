using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// A session command relayed by a front to its remote Authentication Center, with what the front's endpoint presents
/// and the hashes of the secrets it prepared. The secrets themselves never leave the front.
/// <para>
/// Only the remotes of the Authentication Center that have its "AuthCenter" feature can send it.
/// </para>
/// </summary>
public interface IRelaySessionCommand : ICommand<IRelaySessionResult>
{
    /// <summary>
    /// Gets or sets the relayed session command.
    /// </summary>
    IAbstractCommand? Command { get; set; }

    /// <summary>
    /// Gets or sets the bearer token presented to the front: the Authentication Center reads it again.
    /// </summary>
    string? Token { get; set; }

    /// <summary>
    /// Gets or sets the session key presented to the front. Null when the caller presents no session.
    /// </summary>
    string? PresentedSessionKey { get; set; }

    /// <summary>
    /// Gets or sets the hash of the refresh secret presented to the front.
    /// </summary>
    string? PresentedRefreshSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the hash of the binding secret presented to the front.
    /// </summary>
    string? PresentedBindingSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the hash of the refresh secret that the front will use if a session is issued.
    /// </summary>
    string NextRefreshSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the hash of the binding secret that the front will use if a session is issued.
    /// </summary>
    string NextBindingSecretHash { get; set; }

    /// <summary>
    /// Gets or sets the callback URL of the front's endpoint for the remote logins. Null when it cannot receive them.
    /// </summary>
    string? RemoteLoginCallbackUrl { get; set; }

    /// <summary>
    /// Gets or sets the hash of the correlation secret that the front's endpoint prepared for a starting remote login
    /// (an <c>IStartLoginCommand</c> relayed by an endpoint that can receive remote logins). Null otherwise.
    /// </summary>
    string? RemoteLoginCorrelationHash { get; set; }

    /// <summary>
    /// Gets or sets the hash of the correlation secret presented to the front (when a remote login completes).
    /// </summary>
    string? PresentedRemoteLoginHash { get; set; }

    /// <summary>
    /// Gets or sets the origin of the web page that sent the command to the front, as checked by the front's endpoint.
    /// Null when the front's endpoint serves no web page. The Authentication Center only accepts the configured origins.
    /// </summary>
    string? WebOrigin { get; set; }
}
