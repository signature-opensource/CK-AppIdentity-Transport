using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.CKey;

/// <summary>
/// The "CKey" feature: the local, low-level user interface of the AppIdentity store of the process, reached by the ckey
/// tool through a named pipe (see <see cref="CKeyPipeServer"/>). Opt-in, and "Local" only: it is allowed in the
/// "Local:AllowFeatures" of the application, never of a tenant domain (the setup fails). The application's pipe gives
/// access to its tenant domains.
/// </summary>
public sealed class CKeyFeatureDriver : ApplicationIdentityFeatureDriver
{
    CKeyPipeServer? _server;

    /// <summary>
    /// Initializes the driver.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">The key management (the keys of the local parties).</param>
    /// <param name="transport">The transport (the peering issues).</param>
    public CKeyFeatureDriver( ApplicationIdentityService s, KeyManagementFeatureDriver keys, TransportFeatureDriver transport )
        : base( s, isAllowedByDefault: false )
    {
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        var monitor = context.Monitor;
        bool success = true;
        foreach( var tenant in ApplicationIdentityService.TenantDomains )
        {
            success &= CheckNotTenant( monitor, tenant );
        }
        if( success && IsAllowedFeature( ApplicationIdentityService ) )
        {
            _server = new CKeyPipeServer( ApplicationIdentityService );
            _server.Start( monitor );
        }
        return Task.FromResult( success );
    }

    bool CheckNotTenant( IActivityMonitor monitor, ILocalParty tenant )
    {
        if( !IsAllowedFeature( tenant ) ) return true;
        monitor.Error( $"The tenant domain '{tenant}' allows the \"CKey\" feature: it is \"Local\" to the application only (its pipe gives access to the tenant domains)." );
        return false;
    }

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        return Task.FromResult( party is not ILocalParty tenant || CheckNotTenant( context.Monitor, tenant ) );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

    /// <inheritdoc />
    protected override async Task TeardownAsync( FeatureLifetimeContext context )
    {
        if( _server != null ) await _server.StopAsync().ConfigureAwait( false );
    }
}
