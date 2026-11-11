# CK.IO.AuthCenter

The `[Internal]` queries between the parties of a System and their Authentication Center. They are executed by the
endpoint that receives them (`ICommandEndpointOnly`): the handler of the Authentication Center answers for the calling
remote. They are used by [CK.AppIdentity.AuthCenter](../CK.AppIdentity.AuthCenter/README.md) and its two
sides.

| Query | Result | Purpose |
|---|---|---|
| [`IGetRemoteEncryptionKeyQCommand`](IGetRemoteEncryptionKeyQCommand.cs) | [`IPartyEncryptionKeyStatement?`](IGetRemoteEncryptionKeyQCommand.cs) | The key directory: the encryption key of a remote of the Authentication Center (or its own), in a statement it signs. Asked directly or along the "AuthCenter" route. |
| [`IVerifyRoutedProofQCommand`](IVerifyRoutedProofQCommand.cs) | [`IAuthCenterProofStatement?`](IVerifyRoutedProofQCommand.cs) | The verification of the user's proof of a routed command, asked along the "AuthCenter" route by a party without a channel to the Authentication Center: a statement it signs, or null. |
| [`IVerifyCallerProofCommand`](IVerifyCallerProofCommand.cs) | `IAuthenticationInfoPoco?` | The verification of a user's proof relayed by another party (and of the seal of a routed command): the identity proved by the Authentication Center, or null. |
