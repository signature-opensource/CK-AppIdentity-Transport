using System.Collections.Generic;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// A family of login schemes of a <see cref="LocalAuthCenter"/> (OpenID Connect, passkeys...). It is a feature of the
/// local party of its Authentication Center (<see cref="IParty.AddFeature(object)"/>): one instance per local
/// Authentication Center, added by the family's package (its own feature driver).
/// <para>
/// The core of the Authentication Center knows no family: it lists their schemes, asks them whether an unregistered
/// identity may create an account and, for the remote ones (<see cref="IAuthCenterRemoteScheme"/>), dispatches the
/// generic remote login commands to them.
/// </para>
/// </summary>
public interface IAuthCenterScheme
{
    /// <summary>
    /// Gets the name of the <see cref="CK.Core.ILoginProvider"/> that this family drives ("Oidc" for instance). The
    /// scheme listing shows the <see cref="Schemes"/> instead of this provider name.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the schemes that this family makes available ("Oidc.Google" for instance).
    /// </summary>
    IEnumerable<string> Schemes { get; }

    /// <summary>
    /// Gets whether an unregistered identity of a scheme of this family may create an account (through the optional
    /// <see cref="CK.Core.IAutoCreateAccountService"/>). A scheme that belongs to no family never does.
    /// </summary>
    /// <param name="scheme">One of the <see cref="Schemes"/>.</param>
    /// <returns>True if the account creation is allowed for the scheme.</returns>
    bool AllowsAccountCreation( string scheme );
}
