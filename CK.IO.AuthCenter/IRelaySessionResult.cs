using CK.Core;
using System;

namespace CK.IO.AuthCenter;

/// <summary>
/// The result of a <see cref="IRelaySessionCommand"/>: the result of the relayed command and what the front's endpoint
/// must apply.
/// </summary>
public interface IRelaySessionResult : IPoco
{
    /// <summary>
    /// Gets or sets the result of the relayed command.
    /// </summary>
    object? Result { get; set; }

    /// <summary>
    /// Gets or sets the session key when a session has been issued (the front's endpoint uses its prepared secrets).
    /// </summary>
    string? IssuedSessionKey { get; set; }

    /// <summary>
    /// Gets or sets whether the issued session must survive the end of the caller session.
    /// </summary>
    bool RememberMe { get; set; }

    /// <summary>
    /// Gets or sets the end of the issued session.
    /// </summary>
    DateTime RefreshExpires { get; set; }

    /// <summary>
    /// Gets or sets whether the front's endpoint must clear its session secrets.
    /// </summary>
    bool Cleared { get; set; }
}
