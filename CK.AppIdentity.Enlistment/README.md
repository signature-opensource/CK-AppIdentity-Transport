# CK.AppIdentity.Enlistment

The approval of a party that waits to be enlisted in the System. The holder of a pending approval (a party that doesn't
trust the key a remote presented) may be anywhere in the System, the approval page is on the host of the "Enlistment"
route: the pending approvals travel the route up to the host (see the routes of
[CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md#the-routes-and-the-enlistment-url)), and this
package sends the approval back down. The commands are in
[CK.IO.AppIdentity.Enlistment](../CK.IO.AppIdentity.Enlistment/README.md).

> **Any user that reaches the Critical level on the host can approve a party.** No right is checked here: an
> application restricts the approval with a `[CommandHandlingValidator]` of `IApprovePartyCommand`.

## On the host of the approval page

[`PartyApprovalHandlers`](PartyApprovalHandlers.cs) answers the `IGetPendingApprovalsQCommand`: the pending approvals
collected along the "Enlistment" route by the current local party (read with
`TransportFeatureDriver.TryReadPendingApprovalValue`), the oldest first.

[`PartyApprovalHandlers`](PartyApprovalHandlers.cs) handles the `IApprovePartyCommand` (validated by `ICommandAuthCritical`,
refused while impersonating: the operator approves as itself). For each pending approval of the party collected along
the "Enlistment" route of the current local party:

- it builds an `IPartyApprovalStatement` (the party, the fingerprint of its key, the holder, the host, the operator's
  actor identifier and the time) and signs it with the host's identity key (`ILocalKeys.Sign`, see
  [`PartyApprovalStatement`](PartyApprovalStatement.cs): its `Purpose`, its `GetSignedData` and its `Lifetime` of 10
  minutes, which bounds a replay);
- it sends an `IApprovePendingPartyCommand` (the statement and the codes) to the holder along the reversed path of the
  item (`PartyRoutedCommandSender.SendAlongPathAsync` of CK.AppIdentity.Cris), or handles it here when the host is the
  holder.

The result has one outcome per holder: a party that waits on several holders shows one code per holder (a code belongs
to a pair of parties), all the codes go to every holder, and each holder approves with the one that matches.

## On the holder

The `IApprovePendingPartyCommand` is handled with its caller party (`AuthenticationInfo.CallerPartyFullName`: the
reception handler of [CK.AppIdentity.Cris.Authentication](../CK.AppIdentity.Cris.Authentication/README.md) sets it to
the origin of the route). It fails closed:

- the caller party must be the host of the holder's "Enlistment" route, and the statement must name this host and
  this holder (otherwise `Refused`);
- the host's signature is verified when the holder knows its keys (the host itself, or a direct remote): an invalid
  signature is `Refused`. Otherwise the approval is accepted from the chain of hops, each one authenticated by the next;
- the pending approval of the party must still exist (`NoPendingApproval`), and a code approves the key of the
  statement only (`PeeringIssue.TryApprove` with the expected fingerprint): `Approved`, `CodeMismatch` or `NotReady`.

An approval is logged by the holder with its statement and the host's signature: the audit of the enlistment.

## The countersignature of the Authentication Center

An optional `IPartyApprovalCountersignature` (implemented by
[CK.AppIdentity.AuthCenter.Enlistment](../CK.AppIdentity.AuthCenter.Enlistment/README.md)) adds the countersignature of
the Authentication Center to the statement (`CenterCountersignature`): the host obtains it in the operator's request (an
approval it can't countersign is not sent: `Refused`), and the holder that has an Authentication Center requires and
verifies it (otherwise `Refused`). For a "Both" item (the approved party waits on the holder and must approve it too), it
also asks a pin grant of the holder for the approved party: it travels down with the approval
(`IApprovePendingPartyCommand.WaitingPartyGrant`) and the holder hands it over to the approved party (see the authority of
the System in [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md)).

Without the anchor of an Authentication Center, the waiting side of a "both approval" approves the holder locally:
`ckey approve`, or `ckey export trust` / `ckey import trust` (see [CK.AppIdentity.CKey](../CK.AppIdentity.CKey/README.md)).
