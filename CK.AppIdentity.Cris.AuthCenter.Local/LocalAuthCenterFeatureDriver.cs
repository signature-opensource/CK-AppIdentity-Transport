using CK.Core;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The Local side of the "AuthCenter" feature: this application is the Authentication Center of its local parties. It
/// adds a <see cref="LocalAuthCenter"/> to every local party that has an Authentication Center (see <see cref="AuthCenterFeatureDriver"/>),
/// the dynamic tenants included, with the settings of its "AuthCenter" section (see <see cref="AuthCenterOptions"/>).
/// <para>
/// An application has one role: with this package, a local party that allows the feature is its own Authentication Center
/// (a remote of an AuthCenter references CK.AppIdentity.Cris.AuthCenter.Remote instead).
/// </para>
/// </summary>
public sealed class LocalAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly string[] _schemeKeys;

    /// <summary>
    /// Initializes a new <see cref="LocalAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="authCenter">The AuthCenter feature driver (it must be set up before this one).</param>
    /// <param name="schemeConfigurations">The configuration sub-sections declared by the installed scheme families.</param>
    public LocalAuthCenterFeatureDriver( ApplicationIdentityService s,
                                         AuthCenterFeatureDriver authCenter,
                                         IEnumerable<IAuthCenterSchemeConfiguration> schemeConfigurations )
        : base( s, AuthCenterFeatureDriver.ConfigurationKey, isAllowedByDefault: false )
    {
        _schemeKeys = schemeConfigurations.Select( c => c.ConfigurationKey ).ToArray();
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
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null ) return true;
        Throw.DebugAssert( "The role is resolved by the core driver.", center.AuthCenter == local );
        // The settings are the local party's own "AuthCenter" section, in its "Local".
        var settings = local.LocalConfiguration.Configuration.TryGetSection( AuthCenterFeatureDriver.ConfigurationKey );
        if( settings != null && !settings.GetChildren().Any() ) settings = null;
        var options = AuthCenterOptions.Read( monitor, settings, _schemeKeys );
        if( options == null ) return false;
        local.AddFeature( new LocalAuthCenter( monitor, center, options, settings ) );
        return true;
    }
}
