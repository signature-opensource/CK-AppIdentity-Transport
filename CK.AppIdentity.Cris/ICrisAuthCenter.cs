using CK.Auth;
using CK.Core;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The "AuthCenter" feature is carried by a <see cref="ILocalParty"/> and identifies one
/// of its <see cref="ILocalParty.Remotes"/> as the "Authentication Center".
/// </summary>
public interface ICrisAuthCenter
{
    /// <summary>
    /// Gets the remote that is the Authentication Center.
    /// </summary>
    IRemoteParty AuthCenter { get; }
}
