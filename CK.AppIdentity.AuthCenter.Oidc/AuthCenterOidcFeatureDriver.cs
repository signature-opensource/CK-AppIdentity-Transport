using CK.Core;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter.Oidc;

/// <summary>
/// Adds the <see cref="AuthCenterOidc"/> scheme family to every local Authentication Center, the dynamic tenants included,
/// with the schemes of its "AuthCenter:Oidc" section (possibly none). It depends on the <see cref="LocalAuthCenterFeatureDriver"/>:
/// the local Authentication Centers exist when it runs. They share one HTTP client (one connection pool), disposed when the
/// application stops: a removed tenant leaves no client behind.
/// </summary>
public sealed class AuthCenterOidcFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly HttpClient _http;

    /// <summary>
    /// Initializes a new <see cref="AuthCenterOidcFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="authCenter">The AuthCenter feature driver (it must be set up before this one).</param>
    public AuthCenterOidcFeatureDriver( ApplicationIdentityService s, LocalAuthCenterFeatureDriver authCenter )
        : base( s, isAllowedByDefault: true )
    {
        _http = new HttpClient() { Timeout = TimeSpan.FromSeconds( 30 ) };
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
    protected override Task TeardownAsync( FeatureLifetimeContext context )
    {
        _http.Dispose();
        return Task.CompletedTask;
    }

    bool Plug( IActivityMonitor monitor, ILocalParty local )
    {
        var center = local.GetFeature<LocalAuthCenter>();
        if( center == null ) return true;
        var schemes = OidcSchemeOptions.Read( monitor, center.GetSchemeSettings( AuthCenterOidcConfiguration.Key ) );
        if( schemes == null ) return false;
        // Even without schemes: the family hides the "Oidc" provider name in the scheme listing.
        local.AddFeature( new AuthCenterOidc( schemes.Value, _http ) );
        return true;
    }
}
