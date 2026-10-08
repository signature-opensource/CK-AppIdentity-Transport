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

## The local Authentication Center

When the Authentication Center is the local party, `CrisAuthCenter.Local` is a [`LocalAuthCenter`](LocalAuthCenter.cs):
its settings, its sessions and the signing of its tokens. A remote Authentication Center has its own settings: a
settings section on a remote is ignored (with a warning).

### Settings ([`AuthCenterOptions`](AuthCenterOptions.cs))

Read from the `"AuthCenter"` section of the local party (never inherited, static):

| Key | Default | |
|---|---|---|
| `SessionLifetime` | 1 day | The `Expires` of a login. |
| `CriticalLifetime` | 5 minutes | The `CriticalExpires` of a login at `Critical` level. |
| `TokenLifetime` | 10 minutes | The lifetime of a token (at most the session's). |

### Tokens ([`AuthCenterToken`](AuthCenterToken.cs))

A token is the authentication (actual actor, actor, levels, dates, device) and its session identifier, signed by the
Authentication Center for `ICrisAuthCenter.TokenPurpose`. It is the Authentication Center's format, with its own version
number: only `CrisAuthCenter.TryReadToken` reads it (a client gets the authentication from `ISessionResult.Info`).

- **The signature is verified first**, then the audience: the full name of the local party. A token of a tenant domain
  is refused by another one (that also has other keys).
- **The authentication cannot outlive the token:** its dates are clamped to the token expiration.
- **Revocation:** tokens are verified locally, without the session store, so a revoked session stays usable until its
  token expires: at most `TokenLifetime`. The client refreshes its token with `IRefreshSessionCommand`.
- The credential of the signature is embedded in every token (simpler; the "credential sent once" option stays open).

### Sessions ([`AuthCenterSessionStore`](AuthCenterSessionStore.cs))

The sessions are in the `LocalFileStore` of the local party: `AuthCenter/Sessions/{ActualActorId}/{SessionId}`, so all
the sessions of an actor are in one folder. A session holds the **hashes** of the endpoint secrets, never the secrets.
The session identifiers are random (16 bytes, base64url) and checked before being used as file names.

### Opening a session ([`AuthCenterSessionOpener`](AuthCenterSessionOpener.cs))

The `IAuthenticationSessionOpener` of a local Authentication Center. The provider handlers call it
(see CK.Cris.Authentication). It runs the login sequence (the `ILoginProvider` of the scheme, the `ILoginValidator`s, the
account creation or binding of an unregistered user), then stores the session, lets the endpoint issue its secrets and
returns the signed token.

A remote Authentication Center is reached by a relay at the receiving endpoint, before the handlers (to come): a session
command that reaches the opener while the Authentication Center is remote fails closed. It is never executed locally.

### The other session commands ([`AuthCenterSessionService`](AuthCenterSessionService.cs))

They carry nothing: they act on **the current session**, the one whose proof the endpoint presents. The session key
(`"{ActualActorId}.{SessionId}"`, given to `IAuthenticationSessionEndpoint.Issue`) finds it, and the proof must match
**exactly**: the key and both secret hashes (compared in constant time). The key is not a secret.

| Command | |
|---|---|
| `IRefreshSessionCommand` | Reads the actors again (a disabled or removed actor cannot refresh), at most at `Normal` level (the `Critical` level requires a login), rotates the secrets and issues a new token. The impersonation is kept. |
| `ILogoutSessionCommand` | Deletes the session (only when the proof matches: a key alone deletes nothing) and clears the endpoint secrets. |
| `IImpersonateCommand` | Requires the `Critical` level and an `IImpersonationService` that allows it (refused by default). Impersonating oneself is refused. |
| `IClearImpersonationCommand` | Always possible: it can only lower the privileges. |
| `IGetLoginSchemesQCommand` | The provider names of the login providers. Not a session command. |

**A replayed secret revokes the session.** The secrets rotate at each refresh, so a refresh secret is used once: the
right key with other secrets means that the secrets have been stolen (or that two copies of the caller compete). The
session is deleted and the endpoint secrets are cleared. The legitimate caller then has to log in again.

**Not done yet:** the purge of the expired sessions (an expired session is deleted when it is presented).
