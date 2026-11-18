using CK.Core;
using CK.Cris;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Names the route of party commands (<see cref="ICommandTargetParty"/>) that reach a party of the System that is not a
/// remote: when the target of a party command is not a remote of the current local party, the
/// <see cref="ChannelCrisRemoteDispatcher"/> sends it in an <see cref="IPartyRoutedCommand"/> along the route that a
/// provider names (the target must host it), instead of answering "no route". Implemented by the package of the commands:
/// the route is a deployment fact of these commands, not of a caller (no attribute read by reflection).
/// </summary>
[IsMultiple]
public interface IPartyCommandRouteProvider : ISingletonAutoService
{
    /// <summary>
    /// Gets the name of the route of a party command, or null when this provider doesn't know it.
    /// </summary>
    /// <param name="command">The party command.</param>
    /// <returns>The route name or null.</returns>
    string? GetRouteName( IAbstractCommand command );
}
