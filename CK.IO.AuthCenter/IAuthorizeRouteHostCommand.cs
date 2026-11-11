using CK.Auth;
using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Authorizes a party to host a route, System-wide: executed by the Authentication Center, that adds the host to its
/// System list, signs it and sends it to its remotes (every party relays it). A route is accepted only toward an
/// authorized host of its name: a party that announces a route it is not authorized to host is ignored. A Critical
/// operation: the operator's live proof. Who may authorize is decided by the application (a validator of this command).
/// </summary>
public interface IAuthorizeRouteHostCommand : ICommand<int?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the name of the route ("MailSender", "Enlistment"...).
    /// </summary>
    string RouteName { get; set; }

    /// <summary>
    /// Gets or sets the full name of the party authorized to host it.
    /// </summary>
    string HostFullName { get; set; }

    /// <summary>
    /// Gets or sets the target of the route, used only when the Authentication Center doesn't see the description of the
    /// host (the host is not one of its remotes): otherwise, the target is the one the host announces.
    /// </summary>
    string? Target { get; set; }
}

/// <summary>
/// Removes the authorization of a party to host a route, System-wide (see <see cref="IAuthorizeRouteHostCommand"/>). A
/// Critical operation.
/// </summary>
public interface IRemoveRouteHostCommand : ICommand<int?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the name of the route.
    /// </summary>
    string RouteName { get; set; }

    /// <summary>
    /// Gets or sets the full name of the host.
    /// </summary>
    string HostFullName { get; set; }
}
