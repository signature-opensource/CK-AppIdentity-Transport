PartyActors are system wide Actors that represent CK-AppIdentity parties: they are identified by the (case insensitive) `IParty.FullName`.
`CK.sPartyActorEnsure` finds or creates a PartyActor from its full name.
It is a local mapping of the party that owns the actors database: the identity of a party across the System is its full name.
