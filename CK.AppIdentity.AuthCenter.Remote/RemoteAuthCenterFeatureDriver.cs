using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The Remote side of the "AuthCenter" asymmetric feature (see <see cref="AuthCenterFeature"/>): a local party that doesn't
/// allow "AuthCenter" (in its "Local") uses <b>the</b> remote that allows "AuthCenterRemote", if any: this remote is its
/// Authentication Center. The local party gets a <see cref="CrisAuthCenter"/> (shared with this remote) and a
/// <see cref="RemoteAuthCenter"/>. A remote added later can be it. A local party that allows "AuthCenter" is ignored
/// (CK.AppIdentity.AuthCenter.Local handles it).
/// </summary>
public sealed class RemoteAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// Initializes a new <see cref="RemoteAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">
    /// The key management: the keys of the Authentication Center verify its tokens (it must be set up before this driver).
    /// </param>
    public RemoteAuthCenterFeatureDriver( ApplicationIdentityService s, KeyManagementFeatureDriver keys )
        : base( s, AuthCenterFeature.Name )
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
        if( party is ILocalParty local )
        {
            return Task.FromResult( Plug( context, local ) );
        }
        var remote = (IRemoteParty)party;
        if( IsAllowedFeature( remote.Owner ) ) return Task.FromResult( true );
        if( !AuthCenterFeature.CheckNoAuthCenterKey( context.Monitor, remote ) ) return Task.FromResult( false );
        // A remote added later can be the AuthCenter of its local party: the local party can use only one.
        return Task.FromResult( !IsAllowedFeature( remote ) || Plug( context, remote.Owner ) );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        // A destroyed tenant domain takes its AuthCenter (and all its remotes) with it.
        // A destroyed remote that is the AuthCenter of a living local party is an issue.
        if( party is IRemoteParty remote
            && remote.Owner.GetFeature<CrisAuthCenter>() is CrisAuthCenter f
            && f.AuthCenter == remote )
        {
            context.Monitor.Error( $"The AuthCenter '{remote}' has been destroyed: authentication is no more available for '{remote.Owner}'." );
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

    bool Plug( FeatureLifetimeContext context, ILocalParty local )
    {
        if( IsAllowedFeature( local ) ) return true;
        var monitor = context.Monitor;
        bool success = true;
        foreach( var r in local.Remotes )
        {
            success &= AuthCenterFeature.CheckNoAuthCenterKey( monitor, r );
        }
        if( !success || !TryGetFeatureRemote( monitor, local, out var authCenter ) ) return false;
        if( authCenter == null ) return true;
        // Already plugged (a dynamic tenant domain and its remotes).
        if( local.GetFeature<CrisAuthCenter>() is CrisAuthCenter existing )
        {
            Throw.DebugAssert( existing.AuthCenter == authCenter );
            return true;
        }
        var center = CrisAuthCenter.TryCreate( monitor, local, authCenter );
        if( center == null ) return false;
        var remote = new RemoteAuthCenter( center );
        local.AddFeature( remote );
        // Once all the features are set up (the Cris channel to the AuthCenter, the PartyActor registrar if any).
        context.Trampoline.OnSuccess( () => remote.StartPartyActorIdsResolution( context.Monitor ) );
        return true;
    }
}
