using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Optional service that seals the command of a <see cref="IPartyRoutedCommand"/> at its origin and unseals it at its
/// destination: the hops relay what they can't read nor alter (for instance, the authentication packages sign the
/// command with the user's proof, and encrypt it for its destination). It may also seal the result: the destination
/// seals it (<see cref="SealResult"/>), the origin unseals it (<see cref="UnsealResult"/>), the hops relay an
/// <see cref="IPartySealedResult"/>.
/// <para>
/// Without it, the <see cref="IPartyRoutedCommand.SealedCommand"/> is the JSON of the command, in clear, and so is the result.
/// </para>
/// </summary>
public interface ICrisRoutedCommandSeal : ISingletonAutoService
{
    /// <summary>
    /// Seals a routed command at its origin, once the <see cref="ICrisCallEnvelopeContributor"/> filled its envelope: may
    /// replace its <see cref="IPartyRoutedCommand.SealedCommand"/> and change its envelope.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope.</param>
    /// <param name="origin">The originating local party.</param>
    /// <param name="destination">The full name of the party that will execute the command.</param>
    /// <param name="command">The command.</param>
    /// <param name="routed">The routed command (its <see cref="IPartyRoutedCommand.SealedCommand"/> is the JSON of the command).</param>
    /// <param name="envelope">The envelope.</param>
    /// <returns>
    /// Success (false to refuse to send it: the reason is logged) and, when the result will be sealed by the destination,
    /// the state with which the origin unseals it (see <see cref="UnsealResult"/>).
    /// </returns>
    ValueTask<(bool Success, object? ResultState)> SealAsync( IActivityMonitor monitor,
                                                             IServiceProvider services,
                                                             ILocalParty origin,
                                                             string destination,
                                                             IAbstractCommand command,
                                                             IPartyRoutedCommand routed,
                                                             ICrisCallEnvelope envelope );

    /// <summary>
    /// Unseals a routed command at its destination, before its command is read: returns the JSON of the command (the
    /// <see cref="IPartyRoutedCommand.SealedCommand"/> itself when it is not transformed) and may change the envelope.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="sender">The remote that sent it (its last hop).</param>
    /// <param name="routed">The routed command.</param>
    /// <param name="envelope">The envelope.</param>
    /// <returns>
    /// The JSON of the command (null to refuse it: the reason is logged) and, when its result must be sealed, the state
    /// with which the destination seals it (see <see cref="SealResult"/>).
    /// </returns>
    ValueTask<(byte[]? Command, object? ResultState)> UnsealAsync( IActivityMonitor monitor, IRemoteParty sender, IPartyRoutedCommand routed, ICrisCallEnvelope envelope );

    /// <summary>
    /// Seals the result of a routed command at its destination.
    /// </summary>
    /// <param name="resultState">The state given by <see cref="UnsealAsync"/>.</param>
    /// <param name="result">The serialized result.</param>
    /// <returns>The sealed result.</returns>
    byte[] SealResult( object resultState, ReadOnlySpan<byte> result );

    /// <summary>
    /// Unseals the result of a routed command at its origin.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="resultState">The state given by <see cref="SealAsync"/>.</param>
    /// <param name="sealedResult">The sealed result.</param>
    /// <returns>The serialized result, or null when it can't be unsealed (the reason is logged).</returns>
    byte[]? UnsealResult( IActivityMonitor monitor, object resultState, ReadOnlySpan<byte> sealedResult );
}

/// <summary>
/// The sealed result of a <see cref="IPartyRoutedCommand"/> (see <see cref="ICrisRoutedCommandSeal.SealResult"/>): what the
/// hops relay back to the origin, that only the origin can read.
/// </summary>
public interface IPartySealedResult : IPoco
{
    /// <summary>
    /// Gets or sets the sealed result.
    /// </summary>
    byte[] Sealed { get; set; }
}
