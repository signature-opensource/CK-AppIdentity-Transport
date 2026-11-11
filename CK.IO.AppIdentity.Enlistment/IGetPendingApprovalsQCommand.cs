using CK.Auth;
using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Enlistment;

/// <summary>
/// Lists the pending approvals that reach the approval page: the ones collected along the "Enlistment" route by the host
/// of the page. The operator chooses a party here instead of following a link (the enlistment URL reaches the waiting
/// party from a listener it doesn't trust yet). Critical, like the approval: the list exposes the names of the parties.
/// </summary>
public interface IGetPendingApprovalsQCommand : ICommand<IList<IPendingApproval>>, ICommandAuthCritical
{
}

/// <summary>
/// A pending approval: a party (<see cref="PartyFullName"/>) waits for the approval of its key by a holder. A party that
/// waits on several holders has one pending approval per holder (and shows one approval code per holder).
/// </summary>
public interface IPendingApproval : IPoco
{
    /// <summary>
    /// Gets or sets the full name of the party to approve.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the full name of the party that holds the pending approval.
    /// </summary>
    string HolderFullName { get; set; }

    /// <summary>
    /// Gets or sets the fingerprint of the key to approve.
    /// </summary>
    string KeyFingerprint { get; set; }

    /// <summary>
    /// Gets or sets whether the party to approve must also approve the holder ("Both"), or not ("Local").
    /// </summary>
    string Kind { get; set; }

    /// <summary>
    /// Gets or sets since when the key waits (UTC).
    /// </summary>
    DateTime Since { get; set; }

    /// <summary>
    /// Gets the names of the routes that the party states it hosts: the operator can authorize them with its approval
    /// (see <see cref="IApprovePartyCommand.Routes"/>).
    /// </summary>
    IList<string> Routes { get; }
}
