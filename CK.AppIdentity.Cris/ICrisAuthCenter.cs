using CK.Auth;
using CK.Core;

namespace CK.AppIdentity.Cris;

/// <summary>
/// The "AuthCenter" feature is carried by a <see cref="ILocalParty"/> and identifies one
/// of its <see cref="ILocalParty.Remotes"/> as the "Authentication Center" for local
/// (the application or a tenant domain).
/// </summary>
public interface ICrisAuthCenter
{
    /// <summary>
    /// Gets the party identifier of this application for this Authentication Center.
    /// </summary>
    int PartyActorId { get; }
}
