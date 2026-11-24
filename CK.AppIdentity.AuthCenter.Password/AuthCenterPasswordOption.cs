using CK.Core;

namespace CK.AppIdentity.AuthCenter.Password;

/// <summary>
/// The "Password" option of the Authentication Center: the "Basic" scheme family (a user name and a password) of every
/// local Authentication Center, the dynamic tenants included. Enabled by default:
/// <c>"AuthCenter": { "Password": false }</c> turns the scheme off for a party (it is neither listed nor accepted).
/// <para>
/// The option holds the family only: the login provider of the scheme is the backend's (<c>UserPasswordLoginProvider</c>
/// of CK.DB.User.UserPassword for a SQL Server database, or any other), referenced apart. Without it, the scheme is not
/// available.
/// </para>
/// </summary>
[PartyFeatureOption( "Password", TypeActivation.ByDefault )]
public sealed class AuthCenterPasswordOption : IPartyComponentOption<LocalAuthCenterFeatureDriver>, IAuthCenterSchemeFamilyOption
{
    /// <summary>
    /// The name of the scheme (and of its login provider): "Basic".
    /// </summary>
    public const string Scheme = "Basic";

    /// <inheritdoc />
    public IAuthCenterScheme CreateFamily( IActivityMonitor monitor, ILocalParty local ) => new AuthCenterPassword();
}
