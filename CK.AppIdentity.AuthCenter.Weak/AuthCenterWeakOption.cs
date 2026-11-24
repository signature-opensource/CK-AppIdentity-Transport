using CK.Core;

namespace CK.AppIdentity.AuthCenter.Weak;

/// <summary>
/// The "Weak" option of the Authentication Center: the "Weak" scheme family (a weak actor, at most at the Unsafe level)
/// of every local Authentication Center, the dynamic tenants included. Enabled by default:
/// <c>"AuthCenter": { "Weak": false }</c> turns the scheme off for a party (it is neither listed nor accepted).
/// <para>
/// The option holds the family only: the login provider of the scheme is the backend's (<c>WeakActorTable</c> of
/// CK.DB.Actor.WeakActor for a SQL Server database, or any other), referenced apart. Without it, the scheme is not
/// available.
/// </para>
/// </summary>
[PartyFeatureOption( "Weak", TypeActivation.ByDefault )]
public sealed class AuthCenterWeakOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    /// <inheritdoc />
    public IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local ) => new AuthCenterWeak();
}
