# CK.AppIdentity.AuthCenter

The `AuthCenter` feature identifies a Party that centralizes authentication of parties and users
for the application level Cris commands. Only one such (opt-in) feature can exist per `ILocalParty` (that is
the root `IApplicationIdentityService` singleton or one of its `ITenantDomainParty`).

Everything related to authentication lives here, not in CK.AppIdentity.Cris: a Cris channel works without any
authentication concern.

## The two sides

The AuthCenter is a **singleton asymmetric feature** (see
[the asymmetric features of CK.AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/Features/README.md#asymmetric-features)):
one party implements it, the other ones relay the authentication to it, and there is one Authentication Center in a
tenant (a documented property: nothing checks it). The two sides are implemented in packages that depend on this one:

| Package | Content | Feature added to a local party |
|---|---|---|
| this one (core) | The Authentication Center of a local party ([`CrisAuthCenter`](CrisAuthCenter.cs), shared by the two sides), the reading of its tokens, the checks shared by the two sides ([`AuthCenterFeature`](AuthCenterFeature.cs)). No feature driver. | |
| [CK.AppIdentity.AuthCenter.Local](../CK.AppIdentity.AuthCenter.Local/README.md) | A local party that allows "AuthCenter" **is** the Authentication Center: settings, sessions, signing, the session operations, the policy for its remotes. | `CrisAuthCenter`, `LocalAuthCenter` |
| [CK.AppIdentity.AuthCenter.Remote](../CK.AppIdentity.AuthCenter.Remote/README.md) | A local party that doesn't allow it uses **the** remote that is its Authentication Center: its endpoints execute the session commands, the AuthCenter their operations. | `CrisAuthCenter`, `RemoteAuthCenter` |

The two drivers manage the same "AuthCenter" feature. The installed packages give the possible roles, the configuration
of each local party its actual role: the two packages can be referenced by the same application (a tenant can be its
own Authentication Center while another one uses a remote one). A side that is not installed ignores the configuration
of its role (a remote has no operation handler at all).

## Configuration

The feature is opt-in. Its name is `"AuthCenter"` in the `"Local"` of a local party and `"AuthCenterRemote"` on a remote
(in their `"AllowFeatures"`, or in a `"Defaults"` that applies to them, see
[the structural levels and the defaults](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Configuration/README.md#the-structural-levels-and-the-defaults)).
There is no designation key: the `"AuthCenter"` of the `"Local"` gives the role of the local party:

| The local party | Its role | Its remotes that allow `"AuthCenterRemote"` |
|---|---|---|
| allows `"AuthCenter"` | It **is** its own Authentication Center (CK.AppIdentity.AuthCenter.Local). | They use it (they share its `CrisAuthCenter`): a `"Defaults"` that allows `"AuthCenterRemote"` lets all of them use it. |
| doesn't allow it | It relays its authentication to a remote Authentication Center (CK.AppIdentity.AuthCenter.Remote). | **The** remote that is its Authentication Center: at most one. |

A `"Local"` that allows only `"AuthCenterRemote"`, or a remote that allows only `"AuthCenter"`, is a configuration error
(this was the configuration of a remote of an Authentication Center before the asymmetric features). Allowing both names
is not: a `"Defaults"` that applies to a `"Local"` and to its remotes may allow both.

The settings of a local Authentication Center are the `"AuthCenter"` section of its `"Local"` (see
[CK.AppIdentity.AuthCenter.Local](../CK.AppIdentity.AuthCenter.Local/README.md)). A tenant domain is an Authentication
Center only when the feature is allowed for it, in its `"Local"` or in a `"Defaults"` above it.

A remote of an Authentication Center (it references CK.AppIdentity.AuthCenter.Remote):

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Front",
  "Parties": [
    { "PartyName": "Center", "AllowFeatures": "AuthCenterRemote" }, // The Authentication Center.
    { "PartyName": "Box" }
  ]
}
```

An Authentication Center (it references CK.AppIdentity.AuthCenter.Local) whose remotes all use it:

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Center",
  "Defaults": { "AllowFeatures": "AuthCenterRemote" },      // All its remotes use...
  "Local": {
    "AllowFeatures": "AuthCenter",                          // ...this local party: it is the Authentication Center.
    "AuthCenter": { "TokenLifetime": "00:05:00" }
  },
  "Parties": [
    { "PartyName": "Front" }
  ]
}
```

## The feature

A single [`CrisAuthCenter`](CrisAuthCenter.cs) ([`ICrisAuthCenter`](ICrisAuthCenter.cs)) is shared by the local party
and its remotes that allow `"AuthCenterRemote"`. It exposes the `AuthCenter` party, its `Owner` local party and whether
it `IsAvailable`.

`Verify` checks a token signed by the Authentication Center. It is the same call whether the Authentication Center is
the local party or a remote: it delegates to the `IPartyKeys` of the Authentication Center (CK.AppIdentity.KeyManagement).
The purpose is fixed (`ICrisAuthCenter.TokenPurpose`, "CK.AuthCenter.Token"): no other signature of the Authentication
Center can be taken for a token. It fails closed when the feature is not `IsAvailable`. Signing is not here: only a
local Authentication Center signs, with its `ILocalKeys`.

## Rules (the two side drivers, [`AuthCenterFeature`](AuthCenterFeature.cs))

- **Names:** a `"Local"` that allows only `"AuthCenterRemote"`, or a remote that allows only `"AuthCenter"`, is a
  configuration error (checked by CK.AppIdentity).
- **Uniqueness:** a local party that is not the Authentication Center uses at most one remote that allows
  `"AuthCenterRemote"`: more than one is a configuration error (a `"Defaults"` that allows it applies to every remote
  below it).
- **Announced:** the description of a local party that is the Authentication Center announces it (its roles). A local
  party that relays its authentication to a remote checks that the remote announces being the Authentication Center: the
  forgotten `"AuthCenter"` in the `"Local"` of the Authentication Center is an error when it announces its description.
- **Keys:** the Authentication Center must have the "KeyManagement" feature (its keys verify the tokens). A remote
  Authentication Center that is not pinned yet is accepted: `Verify` refuses until it is.
- **No designation:** an `"AuthCenter"` key on a remote, or an `"AuthCenter"` value that is not a section in a `"Local"`
  (like `true`), is a configuration error. A local party that is not the Authentication Center and has no remote that
  allows `"AuthCenterRemote"` has no authentication.
- **Remotes added later:** a remote added later can be the Authentication Center of a local party that has none (Remote
  side); a second one is an error. On the Local side, a remote added later that allows `"AuthCenterRemote"` receives the
  existing feature.
- **Lifetime:** features cannot be removed. When a remote Authentication Center is destroyed (a remote added later, or a
  remote of a dynamic tenant domain), its local party has no more authentication: the feature stays, is no more
  `IsAvailable`, and an error is logged. It fails closed. Destroying a tenant domain takes its Authentication Center
  with it.

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

