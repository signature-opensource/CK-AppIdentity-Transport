# CK.AppIdentity.AuthCenter.Enlistment

The part of the Authentication Center in the enlistment of a party (see
[CK.AppIdentity.Enlistment](../CK.AppIdentity.Enlistment/README.md)): **the Authentication Center countersigns the
statement of an approval**, and the holder of the pending approval requires the countersignature. **It is also the
authority of the System for the peering** (`IPeeringAuthority`, see
[CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md)): it states the approval page of the System
and grants the pins of a "both approval". An application that has both the enlistment and an Authentication Center
references this package, on every party.

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

## A "both approval" in one gesture

When the approved party W waits on the holder H and must approve it too (a "Both" item), the countersignature request
also asks a `PinGrant` (`ICountersignApprovalCommand.WithPinGrant`): "W, whose key is F, may pin H from the checkpoint C".
C is what the Authentication Center knows of H (itself, its pin of a remote, or its anchor), never what the page says: an
H it doesn't know gets no grant (a warning), and W keeps needing a local approval. The grant (3 days) travels down to H
with the approval; H hands it over to W, that verifies it with its anchor of the Authentication Center and pins H. One
gesture on the approval page connects them, nothing is done on W.

## The authenticated approval page

[`AuthCenterPeeringAuthority`](AuthCenterPeeringAuthority.cs) is the `IPeeringAuthority`: the authority of a local party
is its Authentication Center (`CrisAuthCenter`, pinned or anchored).

- **On the Authentication Center,** the `EnlistmentUrlStatement` states the target of its "Enlistment" route: signed on
  demand, again at half-life (3 days) or when the target changes.
- **The other parties** ask it (`IGetEnlistmentUrlQCommand`, on the channel or along the "AuthCenter" route) at start,
  then every hour (every 30 seconds while it can't be obtained), and keep the newest one that verifies. They send it
  instead of the bare enlistment URL: a waiting party that anchors the Authentication Center sees an authenticated URL
  (`PeeringIssue.IsEnlistUrlAuthenticated`), the answer to the phishing of the approval page.

**What a waiting party needs:** `"Local:AuthCenterParty"` and a trust anchor of the Authentication Center
(`"Local:TrustAnchors:{FullName}"`, or `"#Dev"`), and this package. Otherwise, the peering is unchanged.
