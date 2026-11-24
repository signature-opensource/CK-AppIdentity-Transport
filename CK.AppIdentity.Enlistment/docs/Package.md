The approval of a party that waits to be enlisted in a CK-AppIdentity System: the host of the approval page signs the
approval and sends it down to the party that holds the pending approval.

`PartyApprovalHandlers` handles the `IApprovePartyCommand` of the approval page (it signs an approval statement and sends
it down to the holder of the pending approval) and the `IApprovePendingPartyCommand` on the holder (it checks the sender
and the statement, then approves the key with the operator's code). No right is checked: any user that reaches the
Critical level on the host can approve, unless the application adds a validator.
