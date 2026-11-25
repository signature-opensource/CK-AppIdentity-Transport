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
/// of its "AuthCenter" section (see <see cref="AuthCenterOptions"/>). A local party that doesn't declare "AuthCenter" is
/// ignored (CK.AppIdentity.AuthCenter.Remote handles it).
/// <para>
/// The scheme families are options of this driver (<see cref="IAuthCenterSchemeFamilyOption"/>, "AuthCenter:Oidc"...):
/// it adds the family of each one to every local Authentication Center.
/// </para>
/// </summary>
[PartyFeature( AuthCenterFeature.Name, TypeActivation.Optional, Side = FeatureSide.Local )]
[Configuration<AuthCenterConfiguration>]
[Requires<RemoteAuthCenterFeatureDriver>]
public sealed class LocalAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// Initializes a new <see cref="LocalAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">
    /// The key management: the keys of the Authentication Center verify its tokens (it must be set up before this driver).
    /// </param>
    public LocalAuthCenterFeatureDriver( ApplicationIdentityService s,
                                         KeyManagementFeatureDriver keys )
        : base( s )
    {
    }

    /// <inheritdoc />
    protected override async Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        bool success = true;
        foreach( var local in context.GetAllLocals() )
        {
            success &= await PlugAsync( context.Monitor, local ).ConfigureAwait( false );
        }
        return success;
    }

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        if( party is ILocalParty local )
        {
            return PlugAsync( context.Monitor, local );
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
        if( party is ILocalParty local ) Teardown( local );
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context )
    {
        foreach( var local in context.GetAllLocals() )
        {
            Teardown( local );
        }
        return Task.CompletedTask;
    }

    static void Teardown( ILocalParty local )
    {
        if( local.GetFeature<LocalAuthCenter>() is { } center )
        {
            center.OnTeardown();
            local.GetFeature<AuthCenterSystemList>()?.Detach();
        }
    }

    async Task<bool> PlugAsync( IActivityMonitor monitor, ILocalParty local )
    {
        if( !IsAllowedFeature( local ) ) return true;
        bool success = AuthCenterFeature.CheckNoAuthCenterKey( monitor, local );
        foreach( var r in local.Remotes )
        {
            success &= AuthCenterFeature.CheckNoAuthCenterKey( monitor, r );
        }
        if( !success ) return false;
        // The settings: the model of the "AuthCenter" section (checked before the setup: the options of the AuthCenter, the
        // scheme families and the "PasswordLost" of CK.UserProfile.UserPassword.Lost, are its other keys).
        var options = AuthCenterOptions.Create( GetModel<AuthCenterConfiguration>( local ) );
        var center = CrisAuthCenter.TryCreate( monitor, local, local );
        if( center == null ) return false;
        foreach( var r in local.Remotes )
        {
            if( IsAllowedFeature( r ) ) r.AddFeature( center );
        }
        local.AddFeature( new LocalAuthCenter( monitor, center, options ) );
        // The scheme families of its options.
        foreach( var family in GetOptions( local ).OfType<IAuthCenterSchemeFamilyOption>() )
        {
            local.AddFeature( family.CreateFamily( monitor, local ) );
        }
        await AuthCenterSystemList.PlugAsync( monitor, center, null ).ConfigureAwait( false );
        return true;

    }
}
