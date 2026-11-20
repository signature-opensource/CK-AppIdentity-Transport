# Why there are no routes

A System is a star around its Authentication Center: every party that uses the Authentication Center has a link to it,
and the Authentication Center is the hub of the administration of the System (see `IPartyRelay`). A command for a party
that is not a remote goes through the hub, along the path [origin, hub, destination] (`PartyRoutedCommandSender.SendToAsync`).

Nothing is announced beyond one hop: a party's description is what it states to its remotes. What the System needs to
know is a fact of a party (the approval page: a fact of a client application), read where it is needed (the
Authentication Center reads it from the descriptions of its remotes and states it, signed).

The routes (announced, propagated paths to the hosts of a named feature) are gone, and with them their hijacking:

- **Host substitution and path forgery need announcements:** there are none. A path is derived from "who holds whom":
  the origin's remotes and its hub.
- **Only the hub relays, and it knows every identity:** each hop vouches for its predecessor only (the last of `Via` is
  the remote that sent the routed command), the destination believes the chain inside the System, and a chain that
  contains a revoked party is refused by any party.
- **What matters is still signed:** the key events (verified from an anchor), the System list, the approval page
  (`EnlistmentUrlStatement`), the countersignature of an approval: a relay can withhold them, not forge them.

A larger System (a "snowflake") will add delegated hubs (an AuthCenterProxy, a delegate of the Authentication Center for
a scope of parties): the path is then derived from the directory of the hubs, never from announcements.
