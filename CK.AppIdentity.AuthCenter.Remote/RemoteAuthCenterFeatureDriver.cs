using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The Remote side of the "AuthCenter" asymmetric feature (see <see cref="AuthCenterFeature"/>): a local party that doesn't
/// allow "AuthCenter" (in its "Local") uses <b>the</b> remote that allows "AuthCenterRemote", if any: this remote is its
/// Authentication Center. The local party gets a <see cref="CrisAuthCenter"/> (shared with this remote) and a
/// <see cref="RemoteAuthCenter"/>. A remote added later can be it. A local party that allows "AuthCenter" is ignored
/// (CK.AppIdentity.AuthCenter.Local handles it).
/// <para>
/// Without such a remote, the Authentication Center can be designated by its full name: "Local:AuthCenterParty". It must
/// have a trust anchor: the local party gets a <see cref="CrisAuthCenter"/> without channel and an
/// <see cref="AnchoredAuthCenter"/> (what it asks the Authentication Center travels along its route). With such a remote,
/// "Local:AuthCenterParty" must name it.
/// </para>
/// </summary>
public sealed class RemoteAuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// The key of the "Local" configuration that designates the Authentication Center by its full name: "AuthCenterParty".
    /// </summary>
    public const string AuthCenterPartyKey = "AuthCenterParty";

    readonly IServiceProvider _services;

    /// <summary>
    /// Initializes a new <see cref="RemoteAuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">
    /// The key management: the keys of the Authentication Center verify its tokens (it must be set up before this driver).
    /// </param>
    /// <param name="services">
    /// The root services. An Authentication Center designated by its full name needs the <see cref="AnchoredKeyDirectory"/>
    /// and the <see cref="PartyRoutedCommandSender"/> of CK.AppIdentity.Cris (resolved then), and its
    /// <see cref="AnchoredAuthCenter"/> sends its queries from its own scope.
    /// </param>
    public RemoteAuthCenterFeatureDriver( ApplicationIdentityService s, KeyManagementFeatureDriver keys, IServiceProvider services )
        : base( s, AuthCenterFeature.Name )
    {
        _services = services;
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
        var owner = remote.Owner;
        if( IsAllowedFeature( owner ) ) return Task.FromResult( true );
        if( !AuthCenterFeature.CheckNoAuthCenterKey( context.Monitor, remote ) ) return Task.FromResult( false );
        if( !IsAllowedFeature( remote ) ) return Task.FromResult( true );
        // A remote added later can be the AuthCenter of its local party (it is not yet in the Remotes of its local
        // party): the local party can use only one.
        if( owner.GetFeature<CrisAuthCenter>() is CrisAuthCenter existing )
        {
            context.Monitor.Error( $"'{remote}' allows the 'AuthCenterRemote' feature but '{owner}' already uses the AuthCenter '{existing.AuthCenter}': "
                                   + $"a local party can use only one remote AuthCenter." );
            return Task.FromResult( false );
        }
        return Task.FromResult( Attach( context, owner, remote ) );
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
        // Already plugged (a dynamic tenant domain and its remotes).
        if( local.GetFeature<CrisAuthCenter>() != null ) return true;
        var designated = local.LocalConfiguration.Configuration[AuthCenterPartyKey];
        if( authCenter != null )
        {
            if( designated != null && designated != authCenter.FullName.Path )
            {
                monitor.Error( $"'{local}' designates the AuthCenter '{designated}' (\"Local:{AuthCenterPartyKey}\") but its remote '{authCenter}' allows the 'AuthCenterRemote' feature." );
                return false;
            }
            return Attach( context, local, authCenter );
        }
        return designated == null || AttachAnchored( monitor, local, designated );
    }

    bool AttachAnchored( IActivityMonitor monitor, ILocalParty local, string authCenterFullName )
    {
        var directory = (AnchoredKeyDirectory?)_services.GetService( typeof( AnchoredKeyDirectory ) );
        var sender = (PartyRoutedCommandSender?)_services.GetService( typeof( PartyRoutedCommandSender ) );
        if( directory == null || sender == null )
        {
            monitor.Error( $"'{local}' designates the AuthCenter '{authCenterFullName}' by its full name: the AnchoredKeyDirectory and the PartyRoutedCommandSender of CK.AppIdentity.Cris are required." );
            return false;
        }
        var center = CrisAuthCenter.TryCreateAnchored( monitor, local, authCenterFullName, directory );
        if( center == null ) return false;
        local.AddFeature( new AnchoredAuthCenter( center, sender, _services ) );
        return true;
    }

    static bool Attach( FeatureLifetimeContext context, ILocalParty local, IRemoteParty authCenter )
    {
        var monitor = context.Monitor;
        var center = CrisAuthCenter.TryCreate( monitor, local, authCenter );
        if( center == null ) return false;
        local.AddFeature( new RemoteAuthCenter( center ) );
        return true;
    }
}
