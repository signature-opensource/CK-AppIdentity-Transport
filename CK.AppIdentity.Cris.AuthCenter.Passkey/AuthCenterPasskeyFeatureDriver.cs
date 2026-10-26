using CK.Core;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter.Passkey;

/// <summary>
/// Adds the <see cref="AuthCenterPasskey"/> scheme family to every local Authentication Center, the dynamic tenants
/// included, with its "AuthCenter:Passkey" section (possibly absent: the family then has no scheme). It depends on the
/// <see cref="AuthCenterFeatureDriver"/>: the local Authentication Centers exist when it runs.
/// </summary>
public sealed class AuthCenterPasskeyFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly bool _hasStore;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterPasskeyFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="authCenter">The AuthCenter feature driver (it must be set up before this one).</param>
    /// <param name="services">The services: the passkeys are available only with an <see cref="IPasskeyStore"/>.</param>
    public AuthCenterPasskeyFeatureDriver( ApplicationIdentityService s, LocalAuthCenterFeatureDriver authCenter, IServiceProvider services )
        : base( s, isAllowedByDefault: true )
    {
        _hasStore = services.GetService<IPasskeyStore>() != null;
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
        return Task.FromResult( party is not ILocalParty local || Plug( context.Monitor, local ) );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

    bool Plug( IActivityMonitor monitor, ILocalParty local )
    {
        var center = local.GetFeature<LocalAuthCenter>();
        if( center == null ) return true;
        AuthCenterPasskeyOptions? options = null;
        if( center.GetSchemeSettings( AuthCenterPasskeyConfiguration.Key ) is { } section )
        {
            options = AuthCenterPasskeyOptions.Read( monitor, section );
            if( options == null ) return false;
            if( !_hasStore )
            {
                monitor.Warn( $"'{section.Path}' is configured but there is no IPasskeyStore: the passkeys are not available." );
            }
        }
        local.AddFeature( new AuthCenterPasskey( options, _hasStore ) );
        return true;
    }
}
