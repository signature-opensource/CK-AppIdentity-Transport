using CK.Core;
using System.Linq;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The caller party of a command received through a <see cref="CrisChannelFeature"/>: the remote that sent it or, for the
/// inner command of a <see cref="IPartyRoutedCommand"/>, the originating party of the route (the remote that sent it is
/// then the last hop).
/// </summary>
public sealed class CrisCallerParty
{
    internal CrisCallerParty( IRemoteParty sender, IPartyRoutedCommand? route )
    {
        Sender = sender;
        Route = route;
    }

    /// <summary>
    /// Gets the remote that sent the command: the caller party itself, or the last hop of the <see cref="Route"/>.
    /// </summary>
    public IRemoteParty Sender { get; }

    /// <summary>
    /// Gets the routed command that carried the command, or null when the <see cref="Sender"/> is the caller party.
    /// </summary>
    public IPartyRoutedCommand? Route { get; }

    /// <summary>
    /// Gets the full name of the caller party.
    /// </summary>
    public string FullName => Route != null ? Route.Via[0] : Sender.FullName;

    /// <summary>
    /// Returns the sender or "'Origin' (via A > B)".
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => Route is { Via.Count: > 1 }
                                            ? $"{FullName} (via {string.Join( " > ", Route.Via.Skip( 1 ) )})"
                                            : FullName;
}
