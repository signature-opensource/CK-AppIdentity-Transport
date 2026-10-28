using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Optional data sent beside a command over a <see cref="CrisChannelFeature"/>: it is empty here and extended by Poco
/// extensions (for instance with the user's proof, by the authentication packages). The channel knows nothing about
/// what it carries: <see cref="ICrisCallContextContributor"/> fill it, a <see cref="ICrisChannelReceptionHandler"/> reads it.
/// </summary>
public interface ICrisCallContext : IPoco
{
}

/// <summary>
/// Fills the <see cref="ICrisCallContext"/> of a command dispatched to a remote (see <see cref="ChannelCrisRemoteDispatcher"/>).
/// </summary>
[IsMultiple]
public interface ICrisCallContextContributor : ISingletonAutoService
{
    /// <summary>
    /// Contributes to the call context of a command sent to a remote.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the sending scope.</param>
    /// <param name="target">The remote that will receive the command.</param>
    /// <param name="command">The command.</param>
    /// <param name="context">The call context to fill.</param>
    /// <returns>True if something has been set (the call context is sent only when a contributor set something).</returns>
    bool Contribute( IActivityMonitor monitor, IServiceProvider services, IRemoteParty target, IAbstractCommand command, ICrisCallContext context );
}

/// <summary>
/// Optional service that configures the ambient services of a command received from a remote (typically the identity
/// derived from the caller party: see CK.AppIdentity.Cris.Authentication). It is called before the incoming validation;
/// never for an endpoint-only command (it executes in the channel scope, with its <see cref="IRemoteParty"/>).
/// When a hub is returned, the command is validated and executed in a scope built from it, whose <see cref="CurrentLocalParty"/>
/// is the owner of the remote.
/// </summary>
public interface ICrisChannelReceptionHandler : ISingletonAutoService
{
    /// <summary>
    /// Configures the ambient services of a received command, or refuses it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="services">The services of the channel scope.</param>
    /// <param name="caller">The remote that sent the command.</param>
    /// <param name="command">The received command.</param>
    /// <param name="callContext">The call context sent with the command, if any.</param>
    /// <returns>An error that refuses the command, or the ambient services to use (null to keep the channel's ones).</returns>
    ValueTask<(ICrisResultError? Error, AmbientServiceHub? Hub)> ConfigureAsync( IActivityMonitor monitor,
                                                                               IServiceProvider services,
                                                                               IRemoteParty caller,
                                                                               IAbstractCommand command,
                                                                               ICrisCallContext? callContext );
}
