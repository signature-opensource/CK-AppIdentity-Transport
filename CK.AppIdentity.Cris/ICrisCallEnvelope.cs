using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// What travels over a <see cref="CrisChannelFeature"/> for a command: the command and, through Poco extensions, the data
/// sent beside it (for instance the user's proof, by the authentication packages). This is a message, not a command: it
/// is never executed, validated nor deferred; the receiver unwraps it, gives it to the <see cref="ICrisChannelReceptionHandler"/>
/// and executes its <see cref="Command"/>. The channel knows nothing about the extensions: <see cref="ICrisCallEnvelopeContributor"/>
/// fill them.
/// </summary>
public interface ICrisCallEnvelope : IPoco
{
    /// <summary>
    /// Gets or sets the command. It is set by the channel when the envelope is sent.
    /// </summary>
    IAbstractCommand? Command { get; set; }
}

/// <summary>
/// Fills the <see cref="ICrisCallEnvelope"/> of a command dispatched to a remote (see <see cref="ChannelCrisRemoteDispatcher"/>),
/// or sent along a route by its originating party (see <see cref="PartyRoutedCommandSender"/>).
/// </summary>
[IsMultiple]
public interface ICrisCallEnvelopeContributor : ISingletonAutoService
{
    /// <summary>
    /// Contributes to the envelope of a command sent to a remote.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope.</param>
    /// <param name="target">The remote that will receive the command (the first hop of a routed command).</param>
    /// <param name="command">The command (the inner command of a routed one).</param>
    /// <param name="routed">
    /// The routed command that carries the <paramref name="command"/> (its <see cref="IPartyRoutedCommand.SealedCommand"/>
    /// is set), or null when the command is sent to the <paramref name="target"/> itself.
    /// </param>
    /// <param name="envelope">The envelope to fill.</param>
    void Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, IPartyRoutedCommand? routed, ICrisCallEnvelope envelope );
}

/// <summary>
/// Checks the <see cref="ICrisCallEnvelope"/> of a <see cref="IPartyRoutedCommand"/> that this party forwards to its next
/// hop: the counterpart of the <see cref="ICrisCallEnvelopeContributor"/> for the envelope that a hop relays. A party
/// never relays what it can't vouch for: a filter clears the extensions it can't verify (for instance a user's proof).
/// </summary>
[IsMultiple]
public interface ICrisForwardedEnvelopeFilter : ISingletonAutoService
{
    /// <summary>
    /// Checks the envelope of a routed command before it is forwarded, and clears in place what must not be relayed.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="sender">The remote that sent the routed command.</param>
    /// <param name="target">The next hop, that will receive it.</param>
    /// <param name="routed">The routed command.</param>
    /// <param name="envelope">The received envelope, forwarded as is after the filters.</param>
    /// <returns>The awaitable.</returns>
    ValueTask FilterAsync( IActivityMonitor monitor, IRemoteParty sender, IRemoteParty target, IPartyRoutedCommand routed, ICrisCallEnvelope envelope );
}

/// <summary>
/// Optional service that configures the ambient services of a command received from a remote (typically the identity
/// derived from the caller party: see CK.AppIdentity.Cris.Authentication). It is called before the incoming validation;
/// never for an endpoint-only command (it executes in the channel scope, with its <see cref="IRemoteParty"/>).
/// When a hub is returned, the command is validated and executed in a scope built from it, whose <see cref="CurrentLocalParty"/>
/// is the owner of the remote.
/// <para>
/// The inner command of a <see cref="IPartyRoutedCommand"/> requires it, and requires a hub: its caller party is the
/// originating party of the route, not the remote that sent it (see <see cref="CrisCallerParty"/>). Without a reception
/// handler, a routed command is refused.
/// </para>
/// </summary>
public interface ICrisChannelReceptionHandler : ISingletonAutoService
{
    /// <summary>
    /// Configures the ambient services of a received command, or refuses it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the channel scope.</param>
    /// <param name="caller">The caller party: the remote that sent the command, or the originating party of a route.</param>
    /// <param name="command">The received command.</param>
    /// <param name="envelope">The envelope in which the command has been received.</param>
    /// <returns>An error that refuses the command, or the ambient services to use (null to keep the channel's ones).</returns>
    ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                               IServiceProvider services,
                                                                               CrisCallerParty caller,
                                                                               IAbstractCommand command,
                                                                               ICrisCallEnvelope envelope );
}
