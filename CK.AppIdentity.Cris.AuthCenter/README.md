# CK.AppIdentity.Cris.AuthCenter

The `AuthCenter` feature identifies a Party that centralizes authentication of parties and users
for the application level Cris commands. Only one such (opt-in) feature can exist per `ILocalParty` (that is
the root `IApplicationIdentityService` singleton or one of its `ITenantDomain`).

Everything related to authentication lives here, not in CK.AppIdentity.Cris: a Cris channel works without any
authentication concern.

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
and all its remotes that allow the feature. It exposes the `AuthCenter` party, its `Owner` local party, whether it
`IsLocal` and whether it `IsAvailable`.

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
