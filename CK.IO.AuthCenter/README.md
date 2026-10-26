# CK.IO.AuthCenter

The relay protocol between the fronts and their remote Authentication Center. It is used by
[CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md) and its two sides, which describe what the
fronts and the Authentication Center do with it:

- [`IRelaySessionCommand`](IRelaySessionCommand.cs): the relayed session command, the bearer token and the session proof
  presented to the front, and the hashes of the secrets the front prepared (the secrets never leave the front). For the
  remote logins: the callback URL of the front's endpoint, the hash of the correlation it prepared for a starting login
  and the one it presents when the login completes.
- [`IRelaySessionResult`](IRelaySessionResult.cs): the result of the relayed command and what the front's endpoint must
  apply (a session issued with the prepared secrets, or cleared).
- [`IRelayAuthCenterCommand`](IRelayAuthCenterCommand.cs): a relayed command executed by the Authentication Center
  (`ICommandAuthCenter`: the actor's self-service on its own login methods, the login schemes), with the bearer token
  and the hash of the binding secret presented to the front. The Authentication Center accepts only these commands and
  establishes the identity again from the token, its live session and its binding.
  [`IRelayAuthCenterResult`](IRelayAuthCenterResult.cs) carries the command's result.
- [`IGetAuthCenterEncryptionKeyQCommand`](IGetAuthCenterEncryptionKeyQCommand.cs) and
  [`IAuthCenterEncryptionKey`](IAuthCenterEncryptionKey.cs): the current public encryption key of the Authentication Center,
  signed by it. A front encrypts the sensitive fields of the session commands it relays with it.
