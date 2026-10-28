using CK.Cris;

namespace CK.IO.AuthCenter;

/// <summary>
/// Gets the PartyActor identifiers of a remote and of its Authentication Center: a party that has no actors database
/// sends it on connection to its Authentication Center to set its own <c>PartyActorId</c> and the Authentication
/// Center's one. Internal to the System and executed by the receiving endpoint only (the handler answers for the
/// calling remote).
/// </summary>
[Internal]
public interface IGetPartyActorIdsQCommand : ICommand<IPartyActorIds>, ICommandEndpointOnly
{
}
