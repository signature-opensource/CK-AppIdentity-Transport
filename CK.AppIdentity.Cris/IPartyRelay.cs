using CK.Core;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Gives the hub of a local party: the remote through which it reaches the parties of the System that are not its
/// remotes. The hub of the System's administration is its Authentication Center (implemented by
/// CK.AppIdentity.AuthCenter): every party is linked to it, it knows them all.
/// <list type="bullet">
///   <item>
///   The <see cref="ChannelCrisRemoteDispatcher"/> sends a party command (<see cref="ICommandTargetParty"/>) whose target is
///   not a remote of the current local party to its hub, in an <see cref="IPartyRoutedCommand"/> along the path
///   [the local party, its hub, the target]: the hub forwards it when the target is its remote, refuses it otherwise.
///   </item>
///   <item>
///   The hub is the directory of the System: <see cref="IGetAcceptingRemotesQCommand"/> asks it which of its remotes accept
///   a command.
///   </item>
/// </list>
/// Optional: without it (an application without Authentication Center), a party command reaches the remotes only.
/// </summary>
public interface IPartyRelay : ISingletonAutoService
{
    /// <summary>
    /// Gets the hub of a local party, or null when it has none (it is itself the hub, or it has no Authentication Center).
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The hub, a remote of the local party, or null.</returns>
    IRemoteParty? GetHub( ILocalParty local );
}
