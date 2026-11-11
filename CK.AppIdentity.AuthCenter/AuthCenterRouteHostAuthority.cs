using CK.AppIdentity.TransportLayer;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The authority of the routes of the local parties that have an Authentication Center: the hosts authorized by the
/// <see cref="AuthCenterSystemList"/> of the party. A local party without Authentication Center is not ruled here: its
/// "RouteHosts" configuration applies (see <see cref="RouteHosts.TryRead"/>).
/// </summary>
public sealed class AuthCenterRouteHostAuthority : IRouteHostAuthority
{
    /// <inheritdoc />
    public RouteHosts? GetRouteHosts( ILocalParty local ) => local.GetFeature<AuthCenterSystemList>()?.RouteHosts;
}
