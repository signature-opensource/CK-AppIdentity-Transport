using CK.Core;
using CK.Cris;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Transforms a command dispatched to a remote before it is sent (see <see cref="ChannelCrisRemoteDispatcher"/>): for
/// instance, encrypts its sensitive fields for the receiving party. A transformer must not modify the command it
/// receives (it belongs to the caller): it returns a copy when it changes something.
/// </summary>
[IsMultiple]
public interface ICrisOutgoingCommandTransformer : ISingletonAutoService
{
    /// <summary>
    /// Transforms a command to send.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="channel">The channel to the receiving remote.</param>
    /// <param name="command">The command to send.</param>
    /// <returns>The command to send (the same one or a transformed copy), or null when it cannot be sent (the reason is logged).</returns>
    ValueTask<IAbstractCommand?> TransformAsync( IActivityMonitor monitor, CrisChannelFeature channel, IAbstractCommand command );
}

/// <summary>
/// Transforms a command received from a remote, before its execution (and after the check that it is accepted from the
/// remote): for instance, decrypts its sensitive fields.
/// </summary>
[IsMultiple]
public interface ICrisIncomingCommandTransformer : ISingletonAutoService
{
    /// <summary>
    /// Transforms a received command in place.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="caller">The remote that sent the command.</param>
    /// <param name="command">The received command.</param>
    /// <returns>True on success, false to refuse the command (the reason is logged).</returns>
    bool Transform( IActivityMonitor monitor, IRemoteParty caller, IAbstractCommand command );
}
