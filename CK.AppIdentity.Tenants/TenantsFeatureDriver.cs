using CK.AppIdentity.Cris;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Tenants;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Tenants;

/// <summary>
/// The "Tenants" feature: an application that holds Opened tenant templates (see
/// <see cref="IApplicationIdentityService.TenantTemplates"/>) hosts the "Tenants" route on its root party. The route is
/// how the operator's page finds these applications (<see cref="IGetTenantHostsQCommand"/>) and reaches them beyond one
/// hop: the tenant commands are party commands (<see cref="ICommandTargetParty"/>), sent along this route when their
/// target is not a remote (see <see cref="IPartyCommandRouteProvider"/>).
/// <para>
/// A route is accepted only toward an authorized host (the "RouteHosts" of the Authentication Center of the System, or of
/// the local party): the hosts of "Tenants" must be authorized.
/// </para>
/// </summary>
[PartyFeature( RouteName, TypeActivation.ByDefault )]
public sealed class TenantsFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// The name of the route (and of the feature): "Tenants".
    /// </summary>
    public const string RouteName = "Tenants";

    /// <summary>
    /// Initializes a new driver.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    public TenantsFeatureDriver( ApplicationIdentityService s )
        : base( s )
    {
    }

    /// <summary>
    /// The root party of an application that holds Opened tenant templates hosts the "Tenants" route (without target: the
    /// host is what is reached).
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The first phase of its description.</param>
    protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
    {
        if( party is IApplicationIdentityService root && root.TenantTemplates.Count > 0 && IsAllowedFeature( party ) )
        {
            builder.HostRoute( RouteName );
        }
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => Task.FromResult( true );

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.FromResult( true );

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;
}
