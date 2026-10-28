PartyActors are system wide Actors that represent CK-AppIdentity parties: they are identified by the (case insensitive) `IParty.FullName`.
`CK.sPartyActorEnsure` finds or creates a PartyActor from its full name.
`PartyActorFeatureDriver` is the registrar: it sets the `IParty.PartyActorId` of every party of the application when it is set up.
