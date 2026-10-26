using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Sent by a front to its Authentication Center over the Cris channel: a command executed by the Authentication Center
/// (<c>CK.Auth.ICommandAuthCenter</c>, never a session command) and the proof of the caller that sent it to the front.
/// The Authentication Center accepts only these commands, establishes the identity again from the proof (it never
/// trusts the front for it) and executes the command.
/// </summary>
public interface IRelayAuthCenterCommand : ICommand<IRelayAuthCenterResult>
{
    /// <summary>
    /// Gets or sets the relayed command. Its [Sensitive] strings are encrypted for the Authentication Center.
    /// </summary>
    IAbstractCommand? Command { get; set; }

    /// <summary>
    /// Gets or sets the bearer token presented to the front: the Authentication Center reads it again.
    /// </summary>
    string? Token { get; set; }

    /// <summary>
    /// Gets or sets the hash of the binding secret presented to the front: it must be the one of the token and of its
    /// session.
    /// </summary>
    string? PresentedBindingSecretHash { get; set; }
}
