# CK.AppIdentity.Cris.AuthCenter

The `AuthCenter` feature identifies a Party that centralizes authentication of parties and users
for the application level Cris commands. Only one such (opt-in) feature can exist per `ILocalParty` (that is
the root `IApplicationIdentityService` singleton or one of its `ITenantDomainParty`).

Everything related to authentication lives here, not in CK.AppIdentity.Cris: a Cris channel works without any
authentication concern.

## The two sides

The Authentication Center is a singleton within its domain: one party implements it, the other ones use it. The feature
is split accordingly, and **an application has one role**, given by the package it references. The two sides are
implemented in packages that depend on this one:

| Package | Role | Feature added to each local party |
|---|---|---|
| this one (core) | The designation of the Authentication Center, the reading of its tokens. Referenced by both sides. | [`CrisAuthCenter`](CrisAuthCenter.cs) |
| [CK.AppIdentity.Cris.AuthCenter.Local](../CK.AppIdentity.Cris.AuthCenter.Local/README.md) | This application **is** the Authentication Center: settings, sessions, signing, the session operations, the policy for its remotes. | `LocalAuthCenter` |
| [CK.AppIdentity.Cris.AuthCenter.Remote](../CK.AppIdentity.Cris.AuthCenter.Remote/README.md) | This application is a **remote** of an Authentication Center: its endpoints execute the session commands, the AuthCenter their operations. | `RemoteAuthCenter` |

The three drivers manage the same "AuthCenter" feature (`AllowFeatures` doesn't depend on the deployed package). The
role is checked at setup: an AuthCenter application whose local party designates a remote, or a remote whose local party
designates itself, fails to start. The role is chosen by the installed packages (the DI composition), never by a runtime
check: a remote has no operation handler at all. The Local and Remote packages cannot be both referenced (see the
CK.AppIdentity feature drivers).

## Configuration

The feature is opt-in: `"AllowFeatures": "AuthCenter"`. The Authentication Center of a local party is the party whose
**own** configuration has an `"AuthCenter"` key:

- the local party itself: this application is the Authentication Center;
- or one of its remotes: this application delegates its authentication to it.

The value is `true` or a section (that will hold the settings of the Authentication Center). This key is **never
inherited**: a tenant domain that inherits the allowed feature from the root has no Authentication Center until one of
its parties is configured with it.

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Front",
  "AllowFeatures": "AuthCenter",
  "Parties": [
    { "PartyName": "Center", "AuthCenter": true },
    { "PartyName": "Box" }
  ]
}
```

## The feature

A single [`CrisAuthCenter`](CrisAuthCenter.cs) ([`ICrisAuthCenter`](ICrisAuthCenter.cs)) is shared by the local party
and all its remotes that allow the feature. It exposes the `AuthCenter` party, its `Owner` local party and whether
it `IsAvailable`.

`Verify` checks a token signed by the Authentication Center. It is the same call whether the Authentication Center is
the local party or a remote: it delegates to the `IPartyKeys` of the Authentication Center (CK.AppIdentity.KeyManagement).
The purpose is fixed (`ICrisAuthCenter.TokenPurpose`, "CK.AuthCenter.Token"): no other signature of the Authentication
Center can be taken for a token. It fails closed when the feature is not `IsAvailable`. Signing is not here: only a
local Authentication Center signs, with its `ILocalKeys`.

## Rules ([`AuthCenterFeatureDriver`](AuthCenterFeatureDriver.cs))

- **Uniqueness:** two parties configured with `"AuthCenter"` in the same local party is a configuration error.
- **Keys:** the Authentication Center must have the "KeyManagement" feature (its keys verify the tokens). A remote
  Authentication Center that is not pinned yet is accepted: `Verify` refuses until it is.
- **Not allowed:** a party configured with `"AuthCenter"` where the feature is not allowed (on the local party or on
  the remote itself) is a configuration error. An allowed feature without any Authentication Center is a warning.
- **Defined with its local party:** the Authentication Center is set when its local party is set up (at start, or when
  a tenant domain is added with its remotes). A remote added later cannot be the Authentication Center (its setup
  fails); it receives the existing feature.
- **Lifetime:** features cannot be removed. When a remote Authentication Center is destroyed (a remote of a dynamic
  tenant domain), its local party has no more authentication: the feature stays, is no more `IsAvailable`, and an
  error is logged. It fails closed. Destroying a tenant domain takes its Authentication Center with it.


## Tokens ([`AuthCenterToken`](AuthCenterToken.cs))

A token is the authentication (actual actor, actor, levels, dates, device) and its session identifier and the hash of the
binding secret of its session (the endpoints check that the caller presents that secret: a stolen token cannot be used
elsewhere), signed by the
Authentication Center for `ICrisAuthCenter.TokenPurpose`. It is the Authentication Center's format, with its own version
number: only `CrisAuthCenter.ReadTokenAsync` reads it (a client gets the authentication from `ISessionResult.Info`).
The endpoints read the tokens through `IAuthenticationTokenReader` (CK.Cris.Authentication), implemented by
[`AuthCenterTokenReader`](AuthCenterTokenReader.cs) with the AuthCenter of the current local party.

- **The signature is verified first**, then the audience: the full name of the local party. A token of a tenant domain
  is refused by another one (that also has other keys).
- **The authentication cannot outlive the token:** its dates are clamped to the token expiration.
- **Revocation:** tokens are verified locally, without the session store, so a revoked session stays usable until its
  token expires: at most `TokenLifetime`. The client refreshes its token with `IRefreshSessionCommand`.
- The credential of the signature is embedded in every token (simpler; the "credential sent once" option stays open).

The tokens are signed by the Local side (`LocalAuthCenter.CreateToken`).

**The tokens of a remote Authentication Center** (on a remote of it) are verified with the pinned keys of the Authentication
Center. Their audience is the Authentication Center party. After a key rotation, the Authentication Center pushes its new
key events to its connected remotes (the transport does it, see CK.AppIdentity.TransportLayer). A remote that missed them
uses `ReadTokenAsync`: when a token is refused because its issuer is not known (`SignatureVerdict.UnknownIssuer`), the key
events are requested (at most `CrisAuthCenter.KeyEventsTimeout`, 2 seconds) and the token is read again, once.

## The encryption of the sensitive fields ([`AuthCenterFieldEncryption`](AuthCenterFieldEncryption.cs))

The sensitive fields ([Sensitive] strings, like the Basic login password) of the commands that a remote sends to its
Authentication Center are **encrypted** by the remote (in a copy of the command, Remote side) for the Authentication
Center (Local side), so a `tcp:` channel stays acceptable:
- HPKE-like: ephemeral ECDH P-256 with the Authentication Center's encryption key, HKDF-SHA256, AES-256-GCM. A value
  becomes `"ckenc1:..."`. The sent command carries the ciphertext, never the clear value.
- The associated data binds a ciphertext to the Authentication Center, the remote, the command type, the property and
  its creation time: it cannot be moved to another field, command or remote, and one older than 5 minutes is refused.
- The Authentication Center decrypts before validating and executing, and **refuses a clear value**.
- The encryption keys (`AuthCenterEncryptionKeys`, Local side) are in the `LocalFileStore`
  ("AuthCenter/EncryptionKeys"), protected by the local party's data protector. One is published for a day (a new
  one 10 minutes before its end), the previous one still decrypts for 10 more minutes.
- A remote gets the current key with `IGetAuthCenterEncryptionKeyQCommand`: it is signed by the Authentication Center
  for the "CK.AuthCenter.EncryptionKey" purpose (verified like a token, with the same safety net) and cached until
  its signature expires.

