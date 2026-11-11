# CK.AppIdentity.AuthCenter.Enlistment

The part of the Authentication Center in the enlistment of a party (see
[CK.AppIdentity.Enlistment](../CK.AppIdentity.Enlistment/README.md)): **the Authentication Center countersigns the
statement of an approval**, and the holder of the pending approval requires the countersignature. An application that has
both the enlistment and an Authentication Center references this package, on every party.

## What it buys

Without it, the holder verifies the host's signature only when the host is one of its direct remotes; otherwise it
accepts the approval from the chain of hops. With it:

- **The operator is checked by the Authentication Center:** the countersignature is asked in the operator's request, with
  its live proof. A compromised host can't produce an approval without it.
- **The holder verifies the approval whatever the path:** with the keys of its Authentication Center, pinned or anchored
  (see [CK.AppIdentity.AuthCenter](../CK.AppIdentity.AuthCenter/README.md)).

## How

[`AuthCenterApprovalCountersignature`](AuthCenterApprovalCountersignature.cs) is the `IPartyApprovalCountersignature` of
CK.AppIdentity.Enlistment:

- **On the host of the approval page,** once the statement is signed by the host: when the host is the Authentication
  Center, it countersigns at once (the operator's request is executed here, at the Critical level). Otherwise, it sends
  an `ICountersignApprovalCommand` (internal, Critical, its `ActorId` is the operator) to the Authentication Center as a
  routed command: along the path to it when it is a remote, along its `"AuthCenter"` route otherwise. The operator's
  proof travels with it, sealed. When the countersignature can't be obtained, the approval is not sent (`Refused`).
- **On the Authentication Center,** the command is handled: the operator must be at the Critical level, not
  impersonated, the operator of the statement, and the caller party must be the host of the statement. The
  countersignature (`ApprovalCountersignature.Purpose`, `"CK.AuthCenter.PartyApproval"`) covers the same data as the
  host's signature and lives as long (10 minutes). Who may enlist can be checked here by the application: a validator
  of `ICountersignApprovalCommand`.
- **On the holder,** when it has an Authentication Center, the countersignature is required and verified with its keys
  (`CrisAuthCenter.CheckWithKeyEventsAsync`): an approval without it, or with an invalid one, is `Refused`. A holder
  without Authentication Center ignores it.

A System without Authentication Center neither asks nor requires a countersignature.
