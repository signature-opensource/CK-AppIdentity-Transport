# CK.IO.AuthCenter

The relay protocol between the fronts and their remote Authentication Center (see
[CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md)):

- [`IRelaySessionCommand`](IRelaySessionCommand.cs): the relayed session command, the bearer token and the session proof
  presented to the front, and the hashes of the secrets the front prepared (the secrets never leave the front). For the
  remote logins: the callback URL of the front's endpoint, the hash of the correlation it prepared for a starting login
  and the one it presents when the login completes.
- [`IRelaySessionResult`](IRelaySessionResult.cs): the result of the relayed command and what the front's endpoint must
  apply (a session issued with the prepared secrets, or cleared).
- [`IGetAuthCenterEncryptionKeyQCommand`](IGetAuthCenterEncryptionKeyQCommand.cs) and
  [`IAuthCenterEncryptionKey`](IAuthCenterEncryptionKey.cs): the current public encryption key of the Authentication Center,
  signed by it. A front encrypts the sensitive fields of the session commands it relays with it.
