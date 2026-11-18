using CK.AppIdentity.Cris;
using CK.Cris;
using CK.IO.AppIdentity.Tenants;

namespace CK.AppIdentity.Tenants;

/// <summary>
/// Names the "Tenants" route (<see cref="TenantsFeatureDriver.RouteName"/>) of the tenant commands: a tenant command whose
/// target application is not a remote of the current local party travels along it (see <see cref="IPartyCommandRouteProvider"/>).
/// </summary>
public sealed class TenantCommandRouteProvider : IPartyCommandRouteProvider
{
    /// <inheritdoc />
    public string? GetRouteName( IAbstractCommand command )
    {
        return command is IGetTenantInstancesQCommand
                       or ICreateTenantInstanceCommand
                       or ISetTenantIndexCommand
                       or IRemoveTenantInstanceCommand
                ? TenantsFeatureDriver.RouteName
                : null;
    }
}
