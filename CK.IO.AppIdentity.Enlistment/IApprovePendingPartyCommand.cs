using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Enlistment;

/// <summary>
/// Approves a pending party on the party that holds its pending approval: sent by the host of the approval page down the
/// way the pending approval came up, with the statement of the approval and the codes entered by the operator. The holder
/// accepts it only from the host of its "Enlistment" route. Internal to the System.
/// </summary>
[Internal]
public interface IApprovePendingPartyCommand : ICommand<PartyApprovalStatus>
{
    /// <summary>
    /// Gets or sets the statement of the approval, signed by the host of the approval page.
    /// </summary>
    [NullInvalid]
    IPartyApprovalStatement? Statement { get; set; }

    /// <summary>
    /// Gets the codes entered by the operator: they travel beside the statement, never in it.
    /// </summary>
    IList<string> Codes { get; }

    /// <summary>
    /// Gets or sets the pin grant of the Authentication Center for the approved party (it waits on the holder and must
    /// approve it too): the holder hands it over to the approved party at its next attempt. Null without Authentication
    /// Center, or when the holder must not be approved by the approved party.
    /// </summary>
    byte[]? WaitingPartyGrant { get; set; }
}

/// <summary>
/// The statement of an approval: "the operator approved, on the page of the host, the key of the party, pending on the
/// holder", signed by the host. The holder logs it: the audit of the enlistment.
/// </summary>
public interface IPartyApprovalStatement : IPoco
{
    /// <summary>
    /// Gets or sets the full name of the approved party.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the fingerprint of the approved key.
    /// </summary>
    string KeyFingerprint { get; set; }

    /// <summary>
    /// Gets or sets the full name of the party that holds the pending approval.
    /// </summary>
    string HolderFullName { get; set; }

    /// <summary>
    /// Gets or sets the full name of the party that hosts the approval page.
    /// </summary>
    string HostFullName { get; set; }

    /// <summary>
    /// Gets or sets the actor identifier of the operator, on the host.
    /// </summary>
    int OperatorActorId { get; set; }

    /// <summary>
    /// Gets or sets the time of the approval (UTC).
    /// </summary>
    DateTime Time { get; set; }

    /// <summary>
    /// Gets the names of the routes that the operator authorizes the approved party to host (among the ones it states):
    /// the Authentication Center adds them to its System list when it countersigns.
    /// </summary>
    IList<string> Routes { get; }

    /// <summary>
    /// Gets or sets the encoded signature of the statement by the host.
    /// </summary>
    byte[] HostSignature { get; set; }

    /// <summary>
    /// Gets or sets the encoded countersignature of the statement by the Authentication Center (CK.AppIdentity.AuthCenter.Enlistment):
    /// null in a System without Authentication Center.
    /// </summary>
    byte[]? CenterCountersignature { get; set; }
}
