using CK.Core;
using CK.Cris;
using CK.Auth;

namespace CK.IO.AuthCenter;

/// <summary>
/// Revokes the identity of a party (its key event log, named by its identity: the digest of its inception), System-wide:
/// executed by the Authentication Center, that adds an entry to its System list, signs it and sends it to its remotes
/// (every party relays it). The revoked party is cut at the peering everywhere, and its full name is refused in the routed
/// commands and the routes until it is readmitted. A Critical operation: the operator's live proof. Who may revoke is decided
/// by the application (a validator of this command).
/// </summary>
public interface IRevokePartyCommand : ICommand<int?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the party to revoke.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the identity of its key event log to revoke (32 bytes). When null, the identity of the log that the
    /// Authentication Center pins for it (it must then be one of its remotes).
    /// </summary>
    byte[]? Identity { get; set; }
}

/// <summary>
/// Readmits the full name of a revoked party: it incepted again (a new key event log) and comes back by a new enlistment or
/// a new anchor. Its name is no more refused in the routed commands and the routes; its revoked identities stay refused
/// forever. Executed by the Authentication Center (a new System list). A Critical operation, like the revocation.
/// </summary>
public interface IReadmitPartyNameCommand : ICommand<int?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the party to readmit.
    /// </summary>
    string PartyFullName { get; set; }
}

/// <summary>
/// Asks the Authentication Center its current System list (encoded: its data and its signature), null when it has
/// none. Sent periodically by every party that has an Authentication Center, on the channel or along the "AuthCenter"
/// route: a hop that withholds the relayed lists must also block this, and an unreachable center is visible. Internal to
/// the System.
/// </summary>
[Internal]
public interface IGetSystemListQCommand : ICommand<byte[]?>
{
}

/// <summary>
/// Sends the System list of the Authentication Center to a remote: it adopts it when it is newer than its own and
/// verifies (with the keys of the Authentication Center), then relays it to its other remotes. Internal to the System and
/// executed by the receiving endpoint only.
/// </summary>
[Internal]
public interface ISystemListCommand : ICommand, ICommandEndpointOnly
{
    /// <summary>
    /// Gets or sets the encoded System list (its data and the signature of the Authentication Center).
    /// </summary>
    byte[] Encoded { get; set; }
}
