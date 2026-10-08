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
| `SessionLifetime` | 1 day | The `Expires` of a login. The session slides: each refresh moves its end `SessionLifetime` later. |
| `CriticalLifetime` | 5 minutes | The `CriticalExpires` of a login at `Critical` level. |
| `TokenLifetime` | 10 minutes | The lifetime of a token (at most the session's). |

### Tokens ([`AuthCenterToken`](AuthCenterToken.cs))

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

### Sessions ([`AuthCenterSessionStore`](AuthCenterSessionStore.cs))

The sessions are in the `LocalFileStore` of the local party: `AuthCenter/Sessions/{ActualActorId}/{SessionId}`, so all
the sessions of an actor are in one folder. A session holds the **hashes** of the endpoint secrets, never the secrets.
The session identifiers are random (16 bytes, base64url) and checked before being used as file names.

### Opening a session ([`AuthCenterSessionOpener`](AuthCenterSessionOpener.cs))

The `IAuthenticationSessionOpener` of a local Authentication Center. The login handlers call it
(see CK.Cris.Authentication). It runs the login sequence (the `ILoginProvider` of the scheme, the `ILoginValidator`s, the
account creation or binding of an unregistered user), then stores the session, lets the endpoint issue its secrets and
returns the signed token.

**The Basic and Weak login handlers are here temporarily** ([`AuthCenterLoginHandlers`](AuthCenterLoginHandlers.cs)).
A package that implements an authentication provider handles its login commands, so they belong to
CK.DB.User.UserPassword and CK.DB.Actor.WeakActor. But these packages are also used by the old authentication stack, and
a handler needs CK.Cris.Authentication, which defines the same `CK.Auth.CrisAuthenticationService` as the old CK.Cris.Auth
(CS0433 in the generated code of an old-stack application). **When the old stack is retired, these handlers go back to
their DB packages.** The Basic handler opens the session with a `BasicLoginPayload`; the Weak one uses the command as
the payload and never remembers the session. The `IWeakZoneLoginCommand` handler is in CK.DB.Zone.WeakActor.

A session command that reaches the opener while the Authentication Center is remote fails closed: it is never
executed locally (the relay happens before, see below).

### The other session commands ([`AuthCenterSessionService`](AuthCenterSessionService.cs))

They carry nothing: they act on **the current session**, the one whose proof the endpoint presents. The session key
(`"{ActualActorId}.{SessionId}"`, given to `IAuthenticationSessionEndpoint.Issue`) finds it, and the proof must match
**exactly**: the key and both secret hashes (compared in constant time). The key is not a secret.

| Command | |
|---|---|
| `IRefreshSessionCommand` | Reads the actors again (a disabled or removed actor cannot refresh), at most at `Normal` level (the `Critical` level requires a login), slides the session (it ends `SessionLifetime` after the refresh), rotates the secrets and issues a new token. The impersonation is kept. |
| `ILogoutSessionCommand` | Deletes the session (only when the proof matches: a key alone deletes nothing) and clears the endpoint secrets. |
| `IImpersonateCommand` | Requires the `Critical` level and an `IImpersonationService` that allows it (refused by default). Impersonating oneself is refused. |
| `IClearImpersonationCommand` | Always possible: it can only lower the privileges. |
| `IGetLoginSchemesQCommand` | The provider names of the login providers ("Oidc" appears as its configured `Oidc.<Suffix>` schemes). Not a session command. |

**A replayed secret revokes the session.** The secrets rotate at each refresh, so a refresh secret is used once: the
right key with other secrets means that the secrets have been stolen (or that two copies of the caller compete). The
session is deleted and the endpoint secrets are cleared. The legitimate caller then has to log in again.

**The purge of the expired sessions** runs every hour (`LocalAuthCenter.PurgePeriod`, from the first heartbeat) in the
background, never on the agent loop. No setting: every save writes the session file and a session never ends later
than `SessionLifetime` after it, so the files written before "now - SessionLifetime" are the candidates, and their
end is checked before they are deleted. An expired session that is presented is also deleted at once.

### OpenID Connect ([`AuthCenterOidc`](AuthCenterOidc.cs), [`AuthCenterOidcHandlers`](AuthCenterOidcHandlers.cs))

The remote logins (authorization code flow with PKCE). The local Authentication Center alone holds the client
secrets: a front relays the start of a login and the callback, like any session command.

```jsonc
"AuthCenter": {
  "Oidc": {
    "Google": {                                   // The scheme is "Oidc.Google".
      "Authority": "https://accounts.google.com", // https (http only on a loopback address).
      "Issuer": "...",                            // Optional: defaults to the Authority.
      "ClientId": "...",
      "ClientSecret": "...",
      "TokenEndpointAuthMethod": "...",           // Optional: "client_secret_basic" or "client_secret_post" (see below).
      "Scopes": "openid email",                   // "openid" is always included.
      "CallbackUrls": [ "https://app.example.com/.auth/oidc/callback" ]
    }
  }
}
```

1. **`IStartLoginCommand`** (scheme "Oidc.Google"): the endpoint must be able to receive remote logins and its
   `RemoteLoginCallbackUrl` must be one of the `CallbackUrls`; the `ReturnUrl` must be a relative path. A **pending login**
   (state, nonce, PKCE verifier, callback, the hash of the endpoint's correlation secret) is kept in memory for 10 minutes
   (at most 10,000 of them) and the result is the authorization URL.
2. **`IRemoteLoginCallbackCommand`** (built by the endpoint's callback): the pending login is consumed (one use). The
   correlation presented by the endpoint must be the one of the start (**login CSRF**: only the caller that started a
   login can complete it), then the code is redeemed (client secret + PKCE verifier) at the token endpoint (see the client authentication below) and the identity token is
   validated: signature (the provider's keys, read again once on an unknown key), issuer, audience, lifetime, then the
   protocol rules of `OpenIdConnectProtocolValidator` (nonce, `at_hash`, required claims). The messages are
   `OpenIdConnectMessage`: the protocol is the one of Microsoft.IdentityModel (the library of the ASP.NET handler, that
   cannot be used here: it is bound to an HTTP request, the AuthCenter receives Cris commands).
3. The login uses the **"Oidc" login provider**: its payload must have the writable string properties `SchemeSuffix` and
   `Sub` (the payload of CK.DB.User.UserOidc for instance). The session is opened like any login.

**The client authentication at the token endpoint** is `client_secret_basic` by default, the default of the
specification: an HTTP Basic `Authorization` header, whose client id and secret are form-url-encoded before being joined
(RFC 6749 section 2.3.1: a `:` in the id or the secret stays unambiguous). Without `TokenEndpointAuthMethod`, the
`token_endpoint_auth_methods_supported` of the discovery document decides: `client_secret_basic` when it is absent or
announces it, `client_secret_post` (the secret in the body) only when it announces it and not the basic one. A provider
that announces neither (only `private_key_jwt`, `tls_client_auth`...) is refused at the start of the login: the user is
not sent to it. One method per request, the secret is never sent twice.

**One issuer per scheme:** `sub` is unique per issuer only and the identity of an actor is (scheme, sub). The issuer
announced by the provider and the `iss` of the tokens must be exactly the configured one: multi-tenant endpoints (whose
issuer varies) are not supported. **No automatic account creation or binding:** a login succeeds only for an actor
already bound to the identity (unless the application registers an `IAutoCreateAccountService`). The `Code` of the
callback is `[Sensitive]`: it is encrypted in place when relayed.

## The relay to a remote Authentication Center

When the Authentication Center of the current local party is a remote one, the endpoints that accept the session
commands call `IAuthenticationSessionRelay.TryRelay` (CK.Cris.Authentication) **before** the handlers: a front may have
no login provider at all. The protocol is in [CK.IO.AuthCenter](../CK.IO.AuthCenter).

**The front** ([`AuthCenterRelay`](AuthCenterRelay.cs)):
- its endpoint prepares the next secrets: their hashes travel with the command, the secrets stay in the front;
- it sends an `IRelaySessionCommand` (the command, the presented bearer token and proof, the prepared hashes, and for
  the remote logins its callback URL and the correlation hashes) over the
  Cris channel and waits for the Authentication Center (at most `AuthCenterRelay.Timeout`, 30 seconds);
- it applies what the Authentication Center issued (with the prepared secrets) or cleared to its endpoint.
- It fails closed: an unavailable or unreachable Authentication Center is an error, never a local execution.

**The Authentication Center** ([`AuthCenterRelayHandler`](AuthCenterRelayHandler.cs)):
- **Authorization without configuration:** only its remotes that have its "AuthCenter" feature (its fronts) can relay.
- It reads the bearer token again (the front is never trusted), validates the relayed command as an incoming command and
  executes it in its own endpoint ([`AuthCenterRelayDIContainerDefinition`](AuthCenterRelayDIContainerDefinition.cs)):
  the session endpoint is the relayed one (it presents what the front presented, its `Issue` uses the front's prepared
  hashes), the current local party is the Authentication Center, the caller is the front.

`IGetLoginSchemesQCommand` is not a session command: a front simply asks its Authentication Center.

**The tokens of a remote Authentication Center** are verified by the front with the pinned keys of the Authentication
Center. Their audience is the Authentication Center party. After a key rotation, the Authentication Center pushes its new
key events to its connected fronts (the transport does it, see CK.AppIdentity.TransportLayer). A front that missed them
uses `ReadTokenAsync`: when a token is refused because its issuer is not known (`SignatureVerdict.UnknownIssuer`), the key
events are requested (at most `CrisAuthCenter.KeyEventsTimeout`, 2 seconds) and the token is read again, once.

**The sensitive fields** ([Sensitive] strings, like the Basic login password) are **encrypted in place** by the front
for the Authentication Center ([`AuthCenterFieldEncryption`](AuthCenterFieldEncryption.cs)), so a `tcp:` channel stays
acceptable:
- HPKE-like: ephemeral ECDH P-256 with the Authentication Center's encryption key, HKDF-SHA256, AES-256-GCM. A value
  becomes `"ckenc1:..."`. The relayed command carries the ciphertext, never the clear value.
- The associated data binds a ciphertext to the Authentication Center, the front, the command type, the property and
  its creation time: it cannot be moved to another field, command or front, and one older than 5 minutes is refused.
- The Authentication Center decrypts before validating and executing, and **refuses a clear value**.
- The encryption keys ([`AuthCenterEncryptionKeys`](AuthCenterEncryptionKeys.cs)) are in the `LocalFileStore`
  ("AuthCenter/EncryptionKeys"), protected by the local party's data protector. One is published for a day (a new
  one 10 minutes before its end), the previous one still decrypts for 10 more minutes.
- A front gets the current key with `IGetAuthCenterEncryptionKeyQCommand`: it is signed by the Authentication Center
  for the "CK.AuthCenter.EncryptionKey" purpose (verified like a token, with the same safety net) and cached until
  its signature expires.
