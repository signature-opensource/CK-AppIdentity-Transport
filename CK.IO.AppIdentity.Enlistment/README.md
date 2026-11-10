# CK.IO.AppIdentity.Enlistment

The commands of the enlistment of a party in a System. A party that a holder doesn't trust yet waits for an approval;
the pending approvals travel the "Enlistment" route up to the approval page of the System (see the routes of
[CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md#the-routes-and-the-enlistment-url)). An
operator reads the approval codes on the waiting party and enters them on the page: these commands carry them back down.
They are handled by [CK.AppIdentity.Enlistment](../CK.AppIdentity.Enlistment/README.md).

| Type | Role |
|---|---|
| [`IApprovePartyCommand`](IApprovePartyCommand.cs) | Sent by the approval page (`ICommandAuthCritical`): the `PartyFullName` of the party to approve and the `Codes` read on it (one per party it waits on). Its result has one `IPartyApprovalOutcome` per holder of a pending approval of the party: empty when there is none. |
| [`IPartyApprovalOutcome`](IApprovePartyCommand.cs) | The `HolderFullName` and the `PartyApprovalStatus` of the approval on that holder. |
| [`PartyApprovalStatus`](IApprovePartyCommand.cs) | `Approved`, `CodeMismatch`, `NotReady` (the code is not exchanged yet), `NoPendingApproval`, `Unreachable`, `Refused`. |
| [`IApprovePendingPartyCommand`](IApprovePendingPartyCommand.cs) | `[Internal]`: sent by the host of the page to the holder, down the way the pending approval came: the `Statement` and the `Codes` (beside it, never in it). |
| [`IPartyApprovalStatement`](IApprovePendingPartyCommand.cs) | The approved party, the fingerprint of its key, the holder, the host, the operator's actor identifier and the time, with the `HostSignature` and an optional `CenterCountersignature` (null without a trust anchor). |
