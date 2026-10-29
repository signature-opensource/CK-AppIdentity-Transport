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
| this one (core) | The Authentication Center of each local party, the reading of its tokens. Referenced by both sides. | [`CrisAuthCenter`](CrisAuthCenter.cs) |
| [CK.AppIdentity.Cris.AuthCenter.Local](../CK.AppIdentity.Cris.AuthCenter.Local/README.md) | This application **is** the Authentication Center: settings, sessions, signing, the session operations, the policy for its remotes. | `LocalAuthCenter` |
| [CK.AppIdentity.Cris.AuthCenter.Remote](../CK.AppIdentity.Cris.AuthCenter.Remote/README.md) | This application is a **remote** of an Authentication Center: its endpoints execute the session commands, the AuthCenter their operations. | `RemoteAuthCenter` |

The three drivers manage the same "AuthCenter" feature (`AllowFeatures` doesn't depend on the deployed package). The
role is chosen by the installed packages (the DI composition), never by a configuration key nor by a runtime check: a
remote has no operation handler at all. An application that allows the feature but references neither side fails to
start. The Local and Remote packages cannot be both referenced (see the CK.AppIdentity feature drivers).

## Configuration

The feature is opt-in: `"AllowFeatures": "AuthCenter"` in the `"Local"` of a local party, on its remotes concerned, or
in a `"Defaults"` that applies to them (see
[the structural levels and the defaults](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Configuration/README.md#the-structural-levels-and-the-defaults)).
There is no designation key: the Authentication Center of a local party that allows the feature is given by the role of
the application:

- with CK.AppIdentity.Cris.AuthCenter.Local, the local party **is** its own Authentication Center; its remotes that allow
  the feature are its remotes (they share its `CrisAuthCenter`);
- with CK.AppIdentity.Cris.AuthCenter.Remote, **the** remote that allows the feature is its Authentication Center: this
  application delegates its authentication to it.

The settings of a local Authentication Center are the `"AuthCenter"` section of its `"Local"` (see
[CK.AppIdentity.Cris.AuthCenter.Local](../CK.AppIdentity.Cris.AuthCenter.Local/README.md)). A tenant domain has an
Authentication Center only when the feature is allowed for it, in its `"Local"` or in a `"Defaults"` above it.

A remote of an Authentication Center (it references CK.AppIdentity.Cris.AuthCenter.Remote):

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Front",
  "Local": { "AllowFeatures": "AuthCenter" },
  "Parties": [
    { "PartyName": "Center", "AllowFeatures": "AuthCenter" },
    { "PartyName": "Box" }
  ]
}
```

An Authentication Center (it references CK.AppIdentity.Cris.AuthCenter.Local) whose remotes all have the feature:

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Center",
  "Defaults": { "AllowFeatures": "AuthCenter" },            // The application and all its remotes.
  "Local": { "AuthCenter": { "TokenLifetime": "00:05:00" } },
  "Parties": [
    { "PartyName": "Front" }
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

- **Uniqueness:** on the Remote side, more than one remote that allows the feature in the same local party is a
  configuration error (a `"Defaults"` that allows it applies to every remote below it).
- **Keys:** the Authentication Center must have the "KeyManagement" feature (its keys verify the tokens). A remote
  Authentication Center that is not pinned yet is accepted: `Verify` refuses until it is.
- **No designation:** an `"AuthCenter"` key on a remote, or an `"AuthCenter"` value that is not a section in a `"Local"`
  (like `true`), is a configuration error. Remotes that allow the feature while their local party doesn't, or (on the
  Remote side) a local party that allows it for none of its remotes, is a warning: that local party has no authentication.
- **Defined with its local party:** the Authentication Center is set when its local party is set up (at start, or when
  a tenant domain is added with its remotes). A remote added later cannot be the Authentication Center: on the Remote
  side, its setup fails when it allows the feature; on the Local side, it receives the existing feature when it allows it.
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

