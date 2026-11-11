# Route hijacking

A route is announced, not proven. This document says what a compromised party of the System can do with the routes,
what bounds it, and the rule that every use of a route follows.

## How a route is believed

A route ([`PartyRoute`](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Abstractions/PartyRoute.cs)
of CK.AppIdentity) is a name, a target and the path of the parties from the announcing one to the host. The routes travel
in the descriptions of the parties, over this channel, and the transport layer computes the routes of each local party
from those of its connected remotes of the System (see the routes of
[CK.AppIdentity.TransportLayer](../../CK.AppIdentity.TransportLayer/README.md#the-routes-and-the-enlistment-url)).

- `PartyRoute.TryAccept` checks that the first party of the path is the remote that announced it (the channel
  authenticated it), that the local party is not in it, and its length. **The rest of the path is believed.**
- `PartyRoute.SelectBest` keeps the shortest route of a name.
- A local party that hosts a route always uses its own.

So a compromised party of the System can lie in two ways:

| The lie | What it announces | What it would get |
|---|---|---|
| **Host substitution** | That it hosts the route (a path of its own name) | To be the host of the route wherever its route is the shortest: the destination of the commands sent along it, and the target of the route. |
| **Path forgery** | A path to the real host shorter than the real one | To be on the path of the commands sent to the real host. |

## What bounds it

- **A routed command names its destination.** `PartyRoutedCommandSender.SendAsync( ..., routeName, destination )` sets
  `IPartyRoutedCommand.Destination`, the origin and every hop check that their route of that name is hosted by it,
  otherwise the command is refused (fail closed, a `SecurityCritical` warning on a hop). A route is never followed to
  whoever hosts it: host substitution captures nothing that is sent to a named party.
- **The seal is made for the destination,** never for the host of a route: what an `ICrisRoutedCommandSeal` encrypts
  for the destination, a hop can't read nor alter.
- **A conflict is not silent:** the routes of a name that lead to more than one host raise a `SecurityCritical` warning
  that names the hosts and the announcers (CK.AppIdentity.TransportLayer).
- **The answers that matter are signed.** For an example in the packages built on this one: the Authentication Center
  answers along its route with statements signed by its keys, verified from its trust anchor
  ([`AnchoredKeyDirectory`](../AnchoredKeyDirectory.cs) does the same for the key events), and a command that carries a
  user's proof is never sent in clear: without a verified encryption key for the destination, it is not sent.

## What remains

- **Black-holing.** A party on the path of a routed command, or that put itself there by path forgery, can drop it or
  delay it. The sender gets an error (no answer within `ChannelCrisRemoteDispatcher.Timeout`), never a wrong answer to a
  signed request.
- **A route whose host is not known in advance** can be substituted. The "Enlistment" route of CK.AppIdentity.TransportLayer
  is one: a liar that hosts it receives the pending approvals of the parties whose route leads to it (never their
  approval codes) and hides them from the real approval page, and its target, the enlistment URL, is the liar's page
  unless the authority of the System states it (`PeeringIssue.IsEnlistUrlAuthenticated`). An approval still needs the
  code shown by the waiting party, and the countersignature of the Authentication Center when the holder has one.
- **Route hiding.** A party can stop announcing the routes of others: the parties behind it have no route, and say so.

## The rule

**A route is used toward a known party.** Code that sends along a route names the party it expects at its end, and
code that trusts a route without a destination (its target, the items collected along it) treats it as announced by
any party of the System.
