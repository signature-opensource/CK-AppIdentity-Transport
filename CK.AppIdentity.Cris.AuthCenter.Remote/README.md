# CK.AppIdentity.Cris.AuthCenter.Remote

The Remote side of the [AuthCenter feature](../CK.AppIdentity.Cris.AuthCenter/README.md): **this application is a front**
of a remote Authentication Center. Its [`RemoteAuthCenterFeatureDriver`](RemoteAuthCenterFeatureDriver.cs) adds a
[`RemoteAuthCenter`](RemoteAuthCenter.cs) to every local party whose Authentication Center is one of its remotes; a local
party that designates itself is a configuration error (an application has one role: an Authentication Center references
CK.AppIdentity.Cris.AuthCenter.Local).

A front has no login provider, no session and no session handler: every session command and every `ICommandAuthCenter`
command is relayed, never executed here. The protocol is in [CK.IO.AuthCenter](../CK.IO.AuthCenter).

## The relay ([`AuthCenterRelay`](AuthCenterRelay.cs))

It implements `IAuthenticationSessionRelay` and `IAuthCenterCommandRelay` (CK.Cris.Authentication). The endpoints that
accept the session commands call `IAuthenticationSessionRelay.RelayAsync` **before** the handlers:
- its endpoint prepares the next secrets: their hashes travel with the command, the secrets stay in the front;
- it sends an `IRelaySessionCommand` (the command, the presented bearer token and proof, the prepared hashes, and for
  the remote logins its callback URL and the correlation hashes) over the
  Cris channel and waits for the Authentication Center (at most `AuthCenterRelay.Timeout`, 30 seconds);
- it applies what the Authentication Center issued (with the prepared secrets) or cleared to its endpoint.
- It fails closed: a missing, unavailable or unreachable Authentication Center is an error, never a local execution.

The `ICommandAuthCenter` commands (CK.IO.Auth) are what a login point serves: the actor's self-service on its own login
methods (its passkeys, its password) and the login schemes (`IGetLoginSchemesQCommand`). Never the administration: an
Authentication Center is a login point, not an administration point. A front's endpoint calls
`IAuthCenterCommandRelay.RelayAsync` (CK.Cris.Authentication) **after** its incoming validation, and `AuthCenterRelay`
sends an `IRelayAuthCenterCommand`: the command (its [Sensitive] strings encrypted), the presented bearer token and the
hash of the presented binding secret. It fails closed like the session relay.

## The tokens and the encryption key of the Authentication Center

The tokens are verified with the pinned keys of the Authentication Center (see the key events safety net in the core
package). The [Sensitive] strings of a relayed command are encrypted in place for the Authentication Center: the
`RemoteAuthCenter` gets its current encryption key with `IGetAuthCenterEncryptionKeyQCommand`, verifies its signature
("CK.AuthCenter.EncryptionKey" purpose, with the same safety net as the tokens) and caches it until its signature
expires.

## The PartyActor identifiers

A remote of an Authentication Center usually has no actors database. Once the features are set up, its
`RemoteAuthCenter` sends `IGetPartyActorIdsQCommand` on the Cris channel to the Authentication Center (sent as soon as
the channel connects) and sets the `PartyActorId` of its local party and of the Authentication Center with the answer.
`RemoteAuthCenter.PartyActorIdsResolution` completes with true once they are set, false when they cannot be (the
Authentication Center has not resolved them, or there is no Cris channel to it). Nothing is asked when both
identifiers are already set (the application has the CK.DB.AppIdentity registrar).
