using CK.Auth;
using CK.Core;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The "AuthCenter" feature is carried by a <see cref="ILocalParty"/> and all its <see cref="IRemoteParty"/>
/// and identifies one of the <see cref="IParty"/> as the "Authentication Center".
/// <para>
/// Note that the party that is the `AuthCenter` is also decorated by this feature and that a duplicate `AuthCenter` in 
/// a <see cref="ILocalParty"/> is a configuration error.
/// </para>
/// </summary>
public interface ICrisAuthCenter
{
    /// <summary>
    /// Gets the party that is the Authentication Center.
    /// </summary>
    IParty AuthCenter { get; }
}
