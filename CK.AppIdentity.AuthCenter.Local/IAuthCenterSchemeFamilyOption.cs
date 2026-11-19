using CK.Core;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// An option of the Authentication Center (an <see cref="IPartyComponentOption{TOwner}"/> of the
/// <see cref="LocalAuthCenterFeatureDriver"/>, declared by a <see cref="PartyFeatureOptionAttribute"/>) that brings a scheme
/// family: its section is "AuthCenter:&lt;Name&gt;" ("AuthCenter:Oidc"), read by its constructor. The driver creates the
/// family of each local Authentication Center, the dynamic tenants included, and adds it to the features of the party
/// (see <see cref="LocalAuthCenter.SchemeFamilies"/>).
/// </summary>
public interface IAuthCenterSchemeFamilyOption
{
    /// <summary>
    /// Creates the scheme family of a local Authentication Center.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="local">The local party that is the Authentication Center.</param>
    /// <returns>The scheme family.</returns>
    IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local );
}
