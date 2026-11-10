using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Optional service that seals the command of a <see cref="IPartyRoutedCommand"/> at its origin and unseals it at its
/// destination: the hops relay what they can't read nor alter (for instance, the authentication packages sign the
/// command with the user's proof, and encrypt it for its destination).
/// <para>
/// Without it, the <see cref="IPartyRoutedCommand.SealedCommand"/> is the JSON of the command, in clear.
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
    /// <returns>True to send it, false to refuse to send it (the reason is logged).</returns>
    ValueTask<bool> SealAsync( IActivityMonitor monitor,
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
    /// <returns>The JSON of the command, or null to refuse it (the reason is logged).</returns>
    ValueTask<byte[]?> UnsealAsync( IActivityMonitor monitor, IRemoteParty sender, IPartyRoutedCommand routed, ICrisCallEnvelope envelope );
}
