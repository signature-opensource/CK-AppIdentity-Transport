The commands of the enlistment of a party in a CK-AppIdentity System: the approval of a pending party by an operator on
the approval page, and its signed statement sent down to the party that holds the pending approval.

`IApprovePartyCommand` is sent by the approval page with the codes an operator read on the waiting party; the
`[Internal]` `IApprovePendingPartyCommand` carries the signed `IPartyApprovalStatement` down to the party that holds the
pending approval.
