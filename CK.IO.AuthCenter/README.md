# CK.IO.AuthCenter

The `[Internal]` queries between the parties of a System and their Authentication Center. They are executed by the
endpoint that receives them (`ICommandEndpointOnly`): the handler of the Authentication Center answers for the calling
remote. They are used by [CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md) and its two
sides.

| Query | Result | Purpose |
|---|---|---|
| [`IGetAuthCenterEncryptionKeyQCommand`](IGetAuthCenterEncryptionKeyQCommand.cs) | [`IAuthCenterEncryptionKey`](IAuthCenterEncryptionKey.cs) | The current public encryption key of the Authentication Center, signed by it: a remote encrypts with it the sensitive fields of the commands it sends to it. |
| [`IGetPartyActorIdsQCommand`](IGetPartyActorIdsQCommand.cs) | [`IPartyActorIds`](IPartyActorIds.cs) | The PartyActor identifiers of the calling remote and of the Authentication Center (0 when not resolved there): a party that has no actors database sets its `PartyActorId` and the Authentication Center's one with them. |
