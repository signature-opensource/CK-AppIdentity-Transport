# CK.AppIdentity.Enlistment

The approval of a party that waits to be enlisted in the System. The holder of a pending approval (a party that doesn't
trust the key a remote presented) may be anywhere in the System, the approval page is on the party whose client
application has the "Enlistment" fact (see [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md#the-approval-page-and-the-enlistment-url)).
A System is a star around its Authentication Center: the page asks the hub what the parties hold, and this package sends
the approval to the holder, directly or through the hub. The commands are in
[CK.IO.AppIdentity.Enlistment](../CK.IO.AppIdentity.Enlistment/README.md).

> **Any user that reaches the Critical level on the host can approve a party.** No right is checked here: an
> application restricts the approval with a `[CommandHandlingValidator]` of `IApprovePartyCommand`.

## On the host of the approval page

[`EnlistmentItems`](EnlistmentItems.cs) gives what the parties of the System hold for the page: the ones of the current
local party (`TransportFeatureDriver.GetHeldPendingApprovals` and `GetHeldPartyInstances`) and, through its hub (its
Authentication Center, see `IPartyRelay`), the ones of the hub and of its connected remotes (the `[Internal]`
`IGetHeldEnlistmentQCommand`, `IncludeRemotes` asked to the hub). Without hub (the page is on the Authentication Center,
or there is none), it asks its own connected remotes. Nothing is announced nor collected.

[`PartyApprovalHandlers`](PartyApprovalHandlers.cs) answers the `IGetPendingApprovalsQCommand`: the pending approvals of
the System, the oldest first. `IPendingApproval.CompetingKeyCount` is the
number of keys that compete for the approval of the party on its holder (its pending keys and the keys refused since its
places are full): more than one is a sign of an attack (anyone can present keys under the name of a waiting party), or of
a party that restarted with a new key. The operator approves only the code shown by the party it deployed.

[`PartyApprovalHandlers`](PartyApprovalHandlers.cs) handles the `IApprovePartyCommand` (validated by `ICommandAuthCritical`,
refused while impersonating: the operator approves as itself). For each pending approval of the party in the System:

- it builds an `IPartyApprovalStatement` (the party, the fingerprint of its key, the holder, the host, the operator's
  actor identifier, the time) and signs it with the host's identity key (`ILocalKeys.Sign`, see
  [`PartyApprovalStatement`](PartyApprovalStatement.cs): its `Purpose`, its `GetSignedData` and its `Lifetime` of 10
  minutes, which bounds a replay);
- it sends an `IApprovePendingPartyCommand` (the statement and the codes) to the holder, directly or through the hub
  (`PartyRoutedCommandSender.SendToAsync` of CK.AppIdentity.Cris), or handles it here when the host is the holder.

The result has one outcome per holder: a party that waits on several holders shows one code per holder (a code belongs
to a pair of parties), all the codes go to every holder, and each holder approves with the one that matches.

## On the holder

The `IApprovePendingPartyCommand` is handled with its caller party (`AuthenticationInfo.CallerPartyFullName`: the
reception handler of [CK.AppIdentity.Cris.Authentication](../CK.AppIdentity.Cris.Authentication/README.md) sets it to
the origin of the routed command). It fails closed:

- with an Authentication Center, its countersignature of the statement is the authority of the approval (below);
  without, the caller party must be the holder itself or a direct remote whose description has the approval page;
  the statement must name the caller as its host and this holder (otherwise `Refused`);
- the host's signature is verified when the holder knows its keys (the host itself, or a direct remote): an invalid
  signature is `Refused`. Otherwise the approval is accepted from the chain of hops, each one authenticated by the next;
- the pending approval of the party must still exist (`NoPendingApproval`), and a code approves the key of the
  statement only (`PeeringIssue.TryApprove` with the expected fingerprint): `Approved`, `CodeMismatch` or `NotReady`.

An approval is logged by the holder with its statement and the host's signature: the audit of the enlistment.

## The dynamic instances

[`PartyInstanceHandlers`](PartyInstanceHandlers.cs) handles the dynamic instances of the Opened remote templates
(`"MaxInstanceCount"`, see CK.AppIdentity) that have been approved. A candidate is approved like any pending party (its
`IPendingApproval.TemplatePartyName` says that it is a new instance of a template); once approved, its holder has it (see
`EnlistmentItems`):

- on the host of the approval page, `IGetPartyInstancesQCommand` lists them, and `IRemovePartyInstanceCommand` (refused
  while impersonating) sends an `IRemoveHeldPartyInstanceCommand` (with the operator's proof) to each holder, directly or
  through the hub, or handles it here when the host is the holder; its result is the number of holders that removed it;
- on the holder, the `IRemoveHeldPartyInstanceCommand` is Critical (the operator's proof is verified by the holder through
  its Authentication Center) and refused while impersonating: `ILocalParty.RemoveTemplateInstanceAsync` destroys the
  remote and forgets its pinned identity. The instance can call again: it is a new candidate. Without Authentication
  Center, a routed proof can't reach the Critical level: only a page on the holder itself removes its instances.

## The countersignature of the Authentication Center

An optional `IPartyApprovalCountersignature` (implemented by
[CK.AppIdentity.AuthCenter.Enlistment](../CK.AppIdentity.AuthCenter.Enlistment/README.md)) adds the countersignature of
the Authentication Center to the statement (`CenterCountersignature`): the host obtains it in the operator's request (an
approval it can't countersign is not sent: `Refused`), and the holder that has an Authentication Center requires and
verifies it (otherwise `Refused`). An application that has an
Authentication Center (an `ICallerProofVerifier`) must have this countersignature: without it, every approval is refused
(an error), on the host and on the holder. For a "Both" item (the approved party waits on the holder and must approve it too), it
also asks a pin grant of the holder for the approved party: it travels down with the approval
(`IApprovePendingPartyCommand.WaitingPartyGrant`) and the holder hands it over to the approved party (see the authority of
the System in [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md)).

Without the anchor of an Authentication Center, the waiting side of a "both approval" approves the holder locally:
`ckey approve`, or `ckey export trust` / `ckey import trust` (see [CK.AppIdentity.CKey](../CK.AppIdentity.CKey/README.md)).
