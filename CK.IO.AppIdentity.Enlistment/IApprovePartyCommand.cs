using CK.Core;
using CK.Cris;
using CK.Auth;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Enlistment;

/// <summary>
/// Approves a party that waits to be enlisted in the System: sent by the approval page, with the codes an operator read
/// on the waiting party (one per party it waits on: a code belongs to a pair of parties). The host of the page sends the
/// codes to every party that holds a pending approval of the waiting party (see <see cref="IApprovePendingPartyCommand"/>).
/// </summary>
public interface IApprovePartyCommand : ICommand<IList<IPartyApprovalOutcome>>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the party to approve.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets the codes read on the party to approve.
    /// </summary>
    IList<string> Codes { get; }

    /// <summary>
    /// Gets the names of the routes that the operator authorizes the party to host, among the ones it states (see the
    /// pending approvals): the Authentication Center authorizes them with the approval.
    /// </summary>
    IList<string> Routes { get; }
}

/// <summary>
/// The outcome of an <see cref="IApprovePartyCommand"/> for one party that holds a pending approval of the party. The
/// result of the command has one outcome per holder: it is empty when no party holds a pending approval of the party.
/// </summary>
public interface IPartyApprovalOutcome : IPoco
{
    /// <summary>
    /// Gets or sets the full name of the party that holds the pending approval.
    /// </summary>
    string HolderFullName { get; set; }

    /// <summary>
    /// Gets or sets the outcome.
    /// </summary>
    PartyApprovalStatus Status { get; set; }
}

/// <summary>
/// The outcome of an approval on the party that holds the pending approval.
/// </summary>
public enum PartyApprovalStatus
{
    /// <summary>
    /// A code matched the key to approve: it is now trusted by the holder.
    /// </summary>
    Approved,

    /// <summary>
    /// No code matched the key to approve.
    /// </summary>
    CodeMismatch,

    /// <summary>
    /// The code can't be checked yet: the next connection attempt of the parties exchanges it.
    /// </summary>
    NotReady,

    /// <summary>
    /// The holder has no more pending approval of this key.
    /// </summary>
    NoPendingApproval,

    /// <summary>
    /// The holder can't be reached.
    /// </summary>
    Unreachable,

    /// <summary>
    /// The holder refused the approval (its sender or its statement is not the expected one).
    /// </summary>
    Refused
}
