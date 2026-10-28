using CK.AppIdentity;
using CK.Core;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.DB.AppIdentity;

/// <summary>
/// The registrar of the PartyActors: every party of the application (its local parties, the dynamic tenants included,
/// and all their remotes) gets its <see cref="IParty.PartyActorId"/> from the <see cref="PartyActorTable"/> (found or
/// created by its full name) when it is set up.
/// <para>
/// This is generic: a PartyActor is the identity of a party in the actors model, not an authentication notion. The ids
/// are never removed (destroying a PartyActor is an administration decision).
/// </para>
/// <para>
/// This feature is always required: every party gets its identifier. Disallowing it by configuration ("DisallowFeatures")
/// is an error.
/// </para>
/// </summary>
public sealed class PartyActorFeatureDriver : ApplicationIdentityFeatureDriver
{
    readonly PartyActorTable _table;

    /// <summary>
    /// Initializes a new <see cref="PartyActorFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="table">The PartyActor table.</param>
    public PartyActorFeatureDriver( ApplicationIdentityService s, PartyActorTable table )
        : base( s, isAllowedByDefault: true )
    {
        _table = table;
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context ) => RegisterAsync( context );

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => RegisterAsync( context );

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party ) => Task.CompletedTask;

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

    async Task<bool> RegisterAsync( FeatureLifetimeContext context )
    {
        var monitor = context.Monitor;
        var parties = ((IEnumerable<IParty>)context.GetAllLocals()).Concat( context.GetAllRemotes() ).ToList();
        var disallowed = parties.Where( p => !IsAllowedFeature( p ) ).Select( p => p.FullName ).ToList();
        if( disallowed.Count > 0 )
        {
            monitor.Error( $"The PartyActor feature is required: it cannot be disallowed (parties: '{string.Join( "', '", disallowed )}')." );
            return false;
        }
        try
        {
            using var ctx = new SqlStandardCallContext( monitor );
            foreach( var party in parties )
            {
                // The system (1) ensures the PartyActors.
                var id = await _table.EnsureAsync( ctx, 1, party.FullName ).ConfigureAwait( false );
                if( !party.TrySetPartyActorId( monitor, id ) ) return false;
            }
            return true;
        }
        catch( Exception ex )
        {
            monitor.Error( "Unable to register the PartyActors.", ex );
            return false;
        }
    }
}
