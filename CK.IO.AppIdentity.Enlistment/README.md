# CK.IO.AppIdentity.Enlistment

The commands of the enlistment of a party in a System. A party that a holder doesn't trust yet waits for an approval;
the pending approvals travel the "Enlistment" route up to the approval page of the System (see the routes of
[CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md#the-routes-and-the-enlistment-url)). An
operator reads the approval codes on the waiting party and enters them on the page: these commands carry them back down.
They are handled by [CK.AppIdentity.Enlistment](../CK.AppIdentity.Enlistment/README.md).

| Type | Role |
|---|---|
| [`IApprovePartyCommand`](IApprovePartyCommand.cs) | Sent by the approval page (`ICommandAuthCritical`): the `PartyFullName` of the party to approve, the `Codes` read on it (one per party it waits on) and the `Routes` the operator authorizes it to host. Its result has one `IPartyApprovalOutcome` per holder of a pending approval of the party: empty when there is none. |
| [`IGetPendingApprovalsQCommand`](IGetPendingApprovalsQCommand.cs) | Lists the pending approvals that reach the page (`ICommandAuthCritical`: the list exposes the names of the parties): one `IPendingApproval` per item. The operator chooses a party here rather than following a link. |
| [`IPendingApproval`](IGetPendingApprovalsQCommand.cs) | The `PartyFullName`, the `HolderFullName`, the `KeyFingerprint`, the `Kind` ("Local" or "Both"), `Since`, the `Routes` it states that it hosts (the operator can authorize them with the approval) and the `TemplatePartyName` of the Opened template when it is a new dynamic instance (`$Worker-{Name}`). A party that waits on several holders has one per holder. |
| [`IGetPartyInstancesQCommand`](IRemovePartyInstanceCommand.cs) | Lists the approved dynamic instances of the Opened templates that reach the page (`ICommandAuthCritical`): one `IPartyInstance` (`PartyFullName`, `HolderFullName`, `TemplatePartyName`) per holder. |
| [`IRemovePartyInstanceCommand`](IRemovePartyInstanceCommand.cs) | Sent by the approval page (`ICommandAuthCritical`): removes the dynamic instance `PartyFullName` from every holder (its remote is destroyed, its pinned identity forgotten). Its result is the number of holders that removed it. |
| [`IRemoveHeldPartyInstanceCommand`](IRemovePartyInstanceCommand.cs) | `[Internal]`: sent by the host of the page to a holder of the instance, down the way the instance came. |
| [`IPartyApprovalOutcome`](IApprovePartyCommand.cs) | The `HolderFullName` and the `PartyApprovalStatus` of the approval on that holder. |
| [`PartyApprovalStatus`](IApprovePartyCommand.cs) | `Approved`, `CodeMismatch`, `NotReady` (the code is not exchanged yet), `NoPendingApproval`, `Unreachable`, `Refused`. |
| [`IApprovePendingPartyCommand`](IApprovePendingPartyCommand.cs) | `[Internal]`: sent by the host of the page to the holder, down the way the pending approval came: the `Statement` and the `Codes` (beside it, never in it), and the optional `WaitingPartyGrant` (the pin grant of the Authentication Center for a party that waits on the holder, see CK.AppIdentity.AuthCenter.Enlistment). |
| [`IPartyApprovalStatement`](IApprovePendingPartyCommand.cs) | The approved party, the fingerprint of its key, the holder, the host, the operator's actor identifier, the time and the `Routes` it is authorized to host, with the `HostSignature` and an optional `CenterCountersignature` (the Authentication Center's, see CK.AppIdentity.AuthCenter.Enlistment). |
