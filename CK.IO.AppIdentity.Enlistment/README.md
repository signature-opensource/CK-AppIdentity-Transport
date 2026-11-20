# CK.IO.AppIdentity.Enlistment

The commands of the enlistment of a party in a System. A party that a holder doesn't trust yet waits for an approval;
the approval page of the System asks the parties what they hold, through the hub of the System (see
[CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md#the-approval-page-and-the-enlistment-url)). An
operator reads the approval codes on the waiting party and enters them on the page: these commands carry them to the
holders.
They are handled by [CK.AppIdentity.Enlistment](../CK.AppIdentity.Enlistment/README.md).

| Type | Role |
|---|---|
| [`IApprovePartyCommand`](IApprovePartyCommand.cs) | Sent by the approval page (`ICommandAuthCritical`): the `PartyFullName` of the party to approve, and the `Codes` read on it (one per party it waits on). Its result has one `IPartyApprovalOutcome` per holder of a pending approval of the party: empty when there is none. |
| [`IGetPendingApprovalsQCommand`](IGetPendingApprovalsQCommand.cs) | Lists the pending approvals of the System (`ICommandAuthCritical`: the list exposes the names of the parties): one `IPendingApproval` per item. The operator chooses a party here rather than following a link. |
| [`IPendingApproval`](IGetPendingApprovalsQCommand.cs) | The `PartyFullName`, the `HolderFullName`, the `KeyFingerprint`, the `Kind` ("Local" or "Both"), `Since`, the `CompetingKeyCount` and the `TemplatePartyName` of the Opened template when it is a new dynamic instance (`$Worker-{Name}`). A party that waits on several holders has one per holder. |
| [`IGetPartyInstancesQCommand`](IRemovePartyInstanceCommand.cs) | Lists the approved dynamic instances of the Opened templates of the System (`ICommandAuthCritical`): one `IPartyInstance` (`PartyFullName`, `HolderFullName`, `TemplatePartyName`) per holder. |
| [`IRemovePartyInstanceCommand`](IRemovePartyInstanceCommand.cs) | Sent by the approval page (`ICommandAuthCritical`): removes the dynamic instance `PartyFullName` from every holder (its remote is destroyed, its pinned identity forgotten). Its result is the number of holders that removed it. |
| [`IRemoveHeldPartyInstanceCommand`](IRemovePartyInstanceCommand.cs) | `[Internal]`, Critical (the operator's proof travels with it): sent by the host of the page to a holder of the instance, directly or through the hub. |
| [`IOpenEnlistmentTicketCommand`](IEnlistmentTicketCommands.cs) | Sent by the approval page (`ICommandAuthCritical`): opens a pre-authorized enlistment ticket for an expected party (`PartyFullName`, `LifetimeHours`: 24 by default, 168 at most), held by the Authentication Center. Its result, `IEnlistmentTicket` (`Id`, `Ticket`, `Expires`), is the only copy of the ticket: a secret, given to the party at start ("Local:KeyManagement:EnlistTicket"). |
| [`IGetEnlistmentTicketsQCommand`](IEnlistmentTicketCommands.cs) | Lists the tickets of the Authentication Center (`ICommandAuthCritical`): one `IEnlistmentTicketInfo` per ticket (its id, the party, when it was opened, its expiration, its operator, when and by which key it was used; never its key). |
| [`IRevokeEnlistmentTicketCommand`](IEnlistmentTicketCommands.cs) | Revokes a ticket of the Authentication Center (`ICommandAuthCritical`). |
| [`IPartyApprovalOutcome`](IApprovePartyCommand.cs) | The `HolderFullName` and the `PartyApprovalStatus` of the approval on that holder. |
| [`PartyApprovalStatus`](IApprovePartyCommand.cs) | `Approved`, `CodeMismatch`, `NotReady` (the code is not exchanged yet), `NoPendingApproval`, `Unreachable`, `Refused`. |
| [`IApprovePendingPartyCommand`](IApprovePendingPartyCommand.cs) | `[Internal]`: sent by the host of the page to the holder, directly or through the hub: the `Statement` and the `Codes` (beside it, never in it), and the optional `WaitingPartyGrant` (the pin grant of the Authentication Center for a party that waits on the holder, see CK.AppIdentity.AuthCenter.Enlistment). |
| [`IPartyApprovalStatement`](IApprovePendingPartyCommand.cs) | The approved party, the fingerprint of its key, the holder, the host, the operator's actor identifier and the time, with the `HostSignature` and an optional `CenterCountersignature` (the Authentication Center's, see CK.AppIdentity.AuthCenter.Enlistment). |
