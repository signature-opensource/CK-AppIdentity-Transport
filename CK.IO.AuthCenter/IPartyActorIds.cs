using CK.Core;

namespace CK.IO.AuthCenter;

/// <summary>
/// The PartyActor identifiers returned by <see cref="IGetPartyActorIdsQCommand"/>. 0 means "not resolved" (the
/// Authentication Center has no PartyActor registrar, or the party is not registered there).
/// </summary>
public interface IPartyActorIds : IPoco
{
    /// <summary>
    /// Gets or sets the PartyActor identifier of the calling remote.
    /// </summary>
    int CallerPartyActorId { get; set; }

    /// <summary>
    /// Gets or sets the PartyActor identifier of the Authentication Center.
    /// </summary>
    int AuthCenterPartyActorId { get; set; }
}
