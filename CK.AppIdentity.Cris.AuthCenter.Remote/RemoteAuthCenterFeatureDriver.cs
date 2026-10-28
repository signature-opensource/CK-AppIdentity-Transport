using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The Remote side of the "AuthCenter" feature: this application is a remote of an Authentication Center. It adds a
/// <see cref="RemoteAuthCenter"/> to every local party that has an Authentication Center (see <see cref="AuthCenterFeatureDriver"/>),
/// the dynamic tenants included.
/// <para>
/// An application has one role: a local party that is its own Authentication Center is a configuration error here (the
/// application must reference CK.AppIdentity.Cris.AuthCenter.Local instead).
/// </para>
/// </summary>
public sealed class RemoteAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// Initializes a new <see cref="RemoteAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="authCenter">The AuthCenter feature driver (it must be set up before this one).</param>
    public RemoteAuthCenterFeatureDriver( ApplicationIdentityService s, AuthCenterFeatureDriver authCenter )
        : base( s, AuthCenterFeatureDriver.ConfigurationKey, isAllowedByDefault: false )
    {
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        bool success = true;
        foreach( var local in context.GetAllLocals() )
        {
            success &= Plug( context, local );
        }
        return Task.FromResult( success );
    }

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        return Task.FromResult( party is not ILocalParty local || Plug( context, local ) );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

    static bool Plug( FeatureLifetimeContext context, ILocalParty local )
    {
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null ) return true;
        if( center.AuthCenter == local )
        {
            context.Monitor.Error( $"'{local}' is its own AuthCenter but this application is a remote of an AuthCenter (CK.AppIdentity.Cris.AuthCenter.Remote): an application has one role, an AuthCenter references CK.AppIdentity.Cris.AuthCenter.Local." );
            return false;
        }
        var remote = new RemoteAuthCenter( center );
        local.AddFeature( remote );
        // Once all the features are set up (the Cris channel to the AuthCenter, the PartyActor registrar if any).
        context.Trampoline.OnSuccess( () => remote.StartPartyActorIdsResolution( context.Monitor ) );
        return true;
    }
}
