using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The Local side of the "AuthCenter" asymmetric feature (see <see cref="AuthCenterFeature"/>): a local party that allows
/// "AuthCenter" (in its "Local") is its own Authentication Center. It gets a <see cref="CrisAuthCenter"/>, shared with its
/// remotes that allow "AuthCenterRemote" (the dynamic ones included), and a <see cref="LocalAuthCenter"/> with the settings
/// of its "AuthCenter" section (see <see cref="AuthCenterOptions"/>). A local party that doesn't allow "AuthCenter" is
/// ignored (CK.AppIdentity.AuthCenter.Remote handles it).
/// </summary>
public sealed class LocalAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly string[] _schemeKeys;
    readonly IServiceProvider _services;

    /// <summary>
    /// Initializes a new <see cref="LocalAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">
    /// The key management: the keys of the Authentication Center verify its tokens (it must be set up before this driver).
    /// </param>
    /// <param name="services">The root services: the transport computes the routes of a local party again when its route hosts change.</param>
    /// <param name="schemeConfigurations">The configuration sub-sections declared by the installed scheme families.</param>
    public LocalAuthCenterFeatureDriver( ApplicationIdentityService s,
                                         KeyManagementFeatureDriver keys,
                                         IEnumerable<IAuthCenterSchemeConfiguration> schemeConfigurations,
                                         IServiceProvider services )
        : base( s, AuthCenterFeature.Name )
    {
        _services = services;
        _schemeKeys = schemeConfigurations.Select( c => c.ConfigurationKey ).ToArray();
    }

    /// <summary>
    /// A local Authentication Center hosts the <see cref="AuthCenterFeature.RouteName"/> route (without target: the host is
    /// what is reached).
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The first phase of its description.</param>
    protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
    {
        if( IsAllowedFeature( party ) ) builder.HostRoute( AuthCenterFeature.RouteName );
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        bool success = true;
        foreach( var local in context.GetAllLocals() )
        {
            success &= Plug( context.Monitor, local );
        }
        return Task.FromResult( success );
    }

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        if( party is ILocalParty local )
        {
            return Task.FromResult( Plug( context.Monitor, local ) );
        }
        var remote = (IRemoteParty)party;
        if( !IsAllowedFeature( remote.Owner ) ) return Task.FromResult( true );
        if( !AuthCenterFeature.CheckNoAuthCenterKey( context.Monitor, remote ) ) return Task.FromResult( false );
        // A remote added later that uses the local AuthCenter.
        if( IsAllowedFeature( remote ) && remote.Owner.GetFeature<CrisAuthCenter>() is CrisAuthCenter f )
        {
            remote.AddFeature( f );
        }
        return Task.FromResult( true );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        // A destroyed tenant domain takes its AuthCenter with it.
        if( party is ILocalParty local ) local.GetFeature<LocalAuthCenter>()?.OnTeardown();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context )
    {
        foreach( var local in context.GetAllLocals() )
        {
            local.GetFeature<LocalAuthCenter>()?.OnTeardown();
        }
        return Task.CompletedTask;
    }

    bool Plug( IActivityMonitor monitor, ILocalParty local )
    {
        if( !IsAllowedFeature( local ) ) return true;
        bool success = AuthCenterFeature.CheckNoAuthCenterKey( monitor, local );
        foreach( var r in local.Remotes )
        {
            success &= AuthCenterFeature.CheckNoAuthCenterKey( monitor, r );
        }
        if( !success ) return false;
        // The settings are the local party's own "AuthCenter" section, in its "Local".
        var settings = local.LocalConfiguration.Configuration.TryGetSection( AuthCenterFeature.Name );
        if( settings != null && !settings.GetChildren().Any() ) settings = null;
        var options = AuthCenterOptions.Read( monitor, settings, _schemeKeys );
        if( options == null ) return false;
        // The hosts of the routes known at deployment: "AuthCenter:RouteHosts".
        if( !RouteHosts.TryRead( monitor, settings?.TryGetSection( "RouteHosts" ), out var routeHosts ) ) return false;
        var center = CrisAuthCenter.TryCreate( monitor, local, local );
        if( center == null ) return false;
        foreach( var r in local.Remotes )
        {
            if( IsAllowedFeature( r ) ) r.AddFeature( center );
        }
        local.AddFeature( new LocalAuthCenter( monitor, center, options, settings, routeHosts ) );
        AuthCenterSystemList.Plug( monitor, center, null, AuthCenterSystemList.OnRouteHostsChanged( _services, local ) );
        return true;
    }
}
