using CK.Core;
using CK.SqlServer;
using System.Threading.Tasks;

namespace CK.DB.AppIdentity;

/// <summary>
/// Holds the persisted party actors: system wide Actors identified by the full name of a CK-AppIdentity party.
/// </summary>
[SqlTable( "tPartyActor", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
[SqlObjectItem( "vPartyActor" )]
public abstract partial class PartyActorTable : SqlTable
{
    /// <summary>
    /// Finds or creates the PartyActor identified by its full name.
    /// <para>
    /// The <paramref name="fullName"/> must be the party full name as-is (a valid <see cref="CoreApplicationIdentity.FullName"/>):
    /// it is not checked. Since the comparison ignores case, the full names that differ only by case identify the same PartyActor.
    /// </para>
    /// </summary>
    /// <param name="c">The sql call context to use.</param>
    /// <param name="actorId">The current actor identifier.</param>
    /// <param name="fullName">The party full name. Must not be longer than <see cref="CoreApplicationIdentity.FullNameMaxLength"/>.</param>
    /// <returns>The PartyActor identifier.</returns>
    [SqlProcedure( "sPartyActorEnsure" )]
    public abstract Task<int> EnsureAsync( ISqlCallContext c, int actorId, string fullName );

    /// <summary>
    /// Destroys a PartyActor by its identifier (does nothing if the PartyActor does not exist).
    /// The PartyActor is automatically removed from any Groups it may belong to.
    /// </summary>
    /// <param name="c">The sql call context to use.</param>
    /// <param name="actorId">The current actor identifier.</param>
    /// <param name="partyActorId">The PartyActor identifier to destroy.</param>
    [SqlProcedure( "sPartyActorDestroy" )]
    public abstract Task DestroyAsync( ISqlCallContext c, int actorId, int partyActorId );
}
