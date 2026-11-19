using CK.AppIdentity.Cris;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The Authentication Center is the hub of the System's administration (see <see cref="IPartyRelay"/>): every party is
/// linked to it, it knows them all. The hub of a local party is its remote Authentication Center (the
/// <see cref="CrisAuthCenter.AuthCenter"/> of the local party, when it is one of its remotes): a party command for a party
/// that is not a remote goes through it. A local party that is its own Authentication Center, or whose Authentication
/// Center is only anchored (not a remote), has no hub.
/// </summary>
public sealed class AuthCenterRelay : IPartyRelay
{
    /// <inheritdoc />
    public IRemoteParty? GetHub( ILocalParty local ) => local.GetFeature<CrisAuthCenter>()?.AuthCenter as IRemoteParty;
}
