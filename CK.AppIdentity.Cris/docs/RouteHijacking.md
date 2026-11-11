# Route hijacking

A route is announced, not proven. This document says what a compromised party of the System can do with the routes,
what bounds it, and the rule that every use of a route follows.

## How a route is believed

A route ([`PartyRoute`](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Abstractions/PartyRoute.cs)
of CK.AppIdentity) is a name, an optional target and the path of the parties from the announcing one to the host. The
routes travel in the descriptions of the parties, over this channel, and the transport layer computes the routes of each
local party from those of its connected remotes of the System, one per host of a name (see the routes of
[CK.AppIdentity.TransportLayer](../../CK.AppIdentity.TransportLayer/README.md#the-routes-and-the-enlistment-url)).

- `PartyRoute.TryAccept` checks that the first party of the path is the remote that announced it (the channel
  authenticated it), that the local party is not in it, and its length. **The rest of the path is believed.**
- `PartyRoute.SelectBest` keeps the shortest route to a host.
- A local party that hosts a route always uses its own.

So a compromised party of the System can lie in two ways:

| The lie | What it announces | What it would get |
|---|---|---|
| **Host substitution** | That it hosts a route (a path of its own name) | To be a host of the route: the destination of the commands sent to it, and the target of the route (the approval page of the System, for the "Enlistment" route). |
| **Path forgery** | A path to a real host shorter than the real one | To be on the path of the commands sent to that host. |

## What bounds it

- **A route is accepted only toward an authorized host.** The hosts authorized for the routes of a local party
  (`RouteHosts`, CK.AppIdentity.TransportLayer) come from its Authentication Center (a signed list, see
  CK.AppIdentity.AuthCenter), otherwise from its `"RouteHosts"` configuration. A route to another host, or with another
  target, is refused and its announcer is named in a `SecurityCritical` warning: host substitution is impossible when
  the routes have an authority. Without one, the routes are believed as announced (a warning says so).
- **A routed command names its destination.** `PartyRoutedCommandSender.SendAsync( ..., routeName, destination )` sets
  `IPartyRoutedCommand.Destination`, the origin and every hop take the route of that name that leads to it, otherwise
  the command is refused (fail closed, a `SecurityCritical` warning on a hop). A route is never followed to whoever hosts
  it: even where the routes are believed, nothing addressed to a named party reaches another one.
- **The seal is made for the destination,** never for the host of a route: what an `ICrisRoutedCommandSeal` encrypts
  for the destination, a hop can't read nor alter.
- **The answers that matter are signed.** For an example in the packages built on this one: the Authentication Center
  answers along its route with statements signed by its keys, verified from its trust anchor
  ([`AnchoredKeyDirectory`](../AnchoredKeyDirectory.cs) does the same for the key events), and a command that carries a
  user's proof is never sent in clear: without a verified encryption key for the destination, it is not sent.

## What remains

- **Black-holing.** A party on the path of a routed command, or that put itself there by path forgery toward an
  authorized host, can drop it or delay it. The sender gets an error (no answer within
  `ChannelCrisRemoteDispatcher.Timeout`), never a wrong answer to a signed request.
- **A stale list.** A hop can withhold a newer list of the Authentication Center: a newly authorized host is not
  reachable yet (fail closed), and the stale list raises an alarm (see CK.AppIdentity.AuthCenter).
- **Without an authority nor a configuration,** host substitution is possible: a liar that hosts the "Enlistment" route
  receives the pending approvals of the parties whose route leads to it (never their approval codes), and its page
  is offered to the operators. An approval still needs the code shown by the waiting party.
- **Route hiding.** A party can stop announcing the routes of others: the parties behind it have no route, and say so.

## The rule

**A route is used toward a known party.** Code that sends along a route names the party it expects at its end, and
code that trusts what a route carries without a destination (its target, the items collected along it) relies on the
authorization of its host.
