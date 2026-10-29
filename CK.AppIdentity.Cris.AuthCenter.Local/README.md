# CK.AppIdentity.Cris.AuthCenter.Local

The Local side of the [AuthCenter feature](../CK.AppIdentity.Cris.AuthCenter/README.md): **this application is the
Authentication Center** of its local parties (the root and its tenant domains). Its
[`LocalAuthCenterFeatureDriver`](LocalAuthCenterFeatureDriver.cs) adds a [`LocalAuthCenter`](LocalAuthCenter.cs) to every
local party that designates itself (`"AuthCenter": true` or a settings section on the local party); a local party that
designates a remote is a configuration error (an application has one role: a remote of an Authentication Center
references CK.AppIdentity.Cris.AuthCenter.Remote).

The `LocalAuthCenter` holds the settings, the sessions and the signing of the tokens. A remote Authentication Center has
its own settings: a settings section on a remote is ignored (with a warning).

## Settings ([`AuthCenterOptions`](AuthCenterOptions.cs))

Read from the `"AuthCenter"` section of the local party (never inherited, static):

| Key | Default | |
|---|---|---|
| `SessionLifetime` | 1 day | The `Expires` of a login. The session slides: each refresh moves its end `SessionLifetime` later. |
| `CriticalLifetime` | 5 minutes | The `CriticalExpires` of a login at `Critical` level, after the authentication of the user. |
| `CriticalLifetimes:<scheme>` | `CriticalLifetime` | The same, for one scheme (at most the session's). `00:00:00`: the scheme never elevates to `Critical`. |
| `TokenLifetime` | 10 minutes | The lifetime of a token (at most the session's). |
| `RefreshGraceWindow` | 1 minute | How long the previous secrets of a session are accepted, once, after a rotation (0 disables it, at most 5 minutes). See "Sessions". |

### The Critical level is a fresh proof

A login is at the `Critical` level when its provider says so (a user, not a weak actor) **and** the authentication of the
user is recent: the `Critical` level lasts the scheme's critical lifetime after the actual authentication, not after the
login. The direct schemes (Basic, Passkey) verify the credentials: the authentication is now. A remote scheme gives the
time of the authentication at its provider (`RemoteLoginCompletion.AuthenticationTime`: the `auth_time` of an OpenID
Connect identity token): a single sign-on login with an old provider session, or a provider that doesn't tell this time,
is at the `Normal` level. A login started with `IStartLoginCommand.Critical` asks the provider to authenticate the user
again (`IAuthCenterRemoteScheme.StartAsync`'s `critical` parameter).

## Sessions ([`AuthCenterSessionStore`](AuthCenterSessionStore.cs))

The sessions are in the `LocalFileStore` of the local party: `AuthCenter/Sessions/{ActualActorId}/{SessionId}`, so all
the sessions of an actor are in one folder. A session holds the **hashes** of the endpoint secrets, never the secrets.
The session identifiers are random (16 bytes, base64url) and checked before being used as file names.

**Rotation and reuse detection.** Every refresh, impersonation and end of impersonation rotates the secrets. A
presented proof that matches neither the current secrets nor (below) the previous ones **revokes the session**: two
parties hold the same cookies.

**The grace window** (`RefreshGraceWindow`): the answer of a rotation can be lost (a dropped connection, a remote's dispatch
that timed out while the Authentication Center completed). The caller then still has the previous secrets. They are
accepted **once**, within the window after the rotation, by the operations that rotate again (refresh, impersonation, end
of impersonation) and by the logout; the rotation then clears them. An operation that doesn't rotate (the Critical-session
check of a passkey registration) refuses them without revoking. If someone else used them (a thief within the window),
the legitimate caller's secrets become orphaned and its next refresh revokes the session: the reuse detection is delayed,
not lost. The session file keeps the previous hashes and the rotation time (version 2; a version 1 file has none).

**One operation at a time per session:** reading the session, checking the proof, rotating and saving are serialized per
session in the Authentication Center (`AuthCenterSessionStore.LockAsync`): two concurrent rotations cannot both match.

## The session operations ([`AuthCenterOperationHandlers`](AuthCenterOperationHandlers.cs))

The session commands (CK.IO.Authentication) are executed by the endpoint that receives them, with the endpoint packages
of CK-Cris (CK.Cris.Authentication and its per-scheme packages: the login commands are handled there). What needs the
Authentication Center's state is an `[Internal]` **operation command** that the endpoint executes: handled here, locally
when the endpoint is in this application, dispatched to it from a remote (see
[CK.AppIdentity.Cris](../CK.AppIdentity.Cris/README.md)). An operation carries what the endpoint presented and prepared
(the presented proof, the hashes of the next secrets): it is handled with an [`OperationSessionEndpoint`](OperationSessionEndpoint.cs)
built from its data, so the logic is the same wherever it comes from, and its result (`ISessionOperationResult`) tells
the endpoint what to issue or clear.

**Opening a session** ([`AuthCenterSessionIssuer`](AuthCenterSessionIssuer.cs)): `IOpenSessionOperationCommand` carries
the login scheme and the payload of its login provider (the login command itself: it is data, never executed). The
issuer runs the login sequence (the `ILoginProvider` of the scheme, the `ILoginValidator`s, the account creation or
binding of an unregistered user), then stores the session, issues the endpoint's secrets and returns the signed token.
The remote login completion and the passkey login use it too.

## The other session operations ([`AuthCenterSessionService`](AuthCenterSessionService.cs))

They carry nothing but the presented proof: they act on **the current session**. The session key
(`"{ActualActorId}.{SessionId}"`, given to `IAuthenticationSessionEndpoint.Issue`) finds it, and the proof must match
**exactly**: the key and both secret hashes (compared in constant time). The key is not a secret.

| Operation | |
|---|---|
| `IRefreshSessionOperationCommand` | Reads the actors again (a disabled or removed actor cannot refresh), at most at `Normal` level (the `Critical` level requires a login), slides the session (it ends `SessionLifetime` after the refresh), rotates the secrets and issues a new token. The impersonation is kept. |
| `ILogoutSessionOperationCommand` | Deletes the session (only when the proof matches: a key alone deletes nothing) and clears the endpoint secrets. |
| `IImpersonateOperationCommand` | Requires the `Critical` level and an `IImpersonationService` that allows it (refused by default). Impersonating oneself is refused. From a remote, the `Critical` level requires the user's proof (see below). |
| `IClearImpersonationOperationCommand` | Always possible: it can only lower the privileges. |

`IGetLoginSchemesQCommand` ([`AuthCenterCommandHandlers`](AuthCenterCommandHandlers.cs)) is not an operation: it
answers the provider names of the login providers; the provider of a scheme family appears as the schemes of its family
("Oidc" as its configured `Oidc.<Suffix>` schemes). Each `ILoginSchemeInfo` has the scheme's critical lifetime: zero
for the "Weak" scheme (its actors are weak) and for a scheme configured with `00:00:00`.

**A replayed secret revokes the session.** The secrets rotate at each refresh, so a refresh secret is used once: the
right key with other secrets means that the secrets have been stolen (or that two copies of the caller compete). The
session is deleted and the endpoint secrets are cleared. The legitimate caller then has to log in again.

**The purge of the expired sessions** runs every hour (`LocalAuthCenter.PurgePeriod`, from the first heartbeat) in the
background, never on the agent loop. No setting: every save writes the session file and a session never ends later
than `SessionLifetime` after it, so the files written before "now - SessionLifetime" are the candidates, and their
end is checked before they are deleted. An expired session that is presented is also deleted at once.

## Scheme families ([`IAuthCenterScheme`](IAuthCenterScheme.cs))

This package knows no login technology: the login providers (`ILoginProvider`) do, and each family of schemes is a
package of its own ("Package First": a simple application references little). For concrete families
built on this package, see [CK.AppIdentity.Cris.AuthCenter.Oidc](../CK.AppIdentity.Cris.AuthCenter.Oidc/README.md) for
the "Oidc.&lt;Suffix&gt;" schemes and [CK.AppIdentity.Cris.AuthCenter.Passkey](../CK.AppIdentity.Cris.AuthCenter.Passkey/README.md)
for the "Passkey" one.
`AuthCenterSessionService.GetCriticalSessionAsync` (a Critical, not impersonated session) is public for the families that
handle their own commands, and so is `AuthCenterResults`, from the core
[CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md).

- **A family is a feature of the local party** of its Authentication Center (`LocalAuthCenter.SchemeFamilies`,
  `FindSchemeFamily`): one instance per local Authentication Center (the root and every tenant), added by the family's
  own feature driver, that depends on the `LocalAuthCenterFeatureDriver`.
- **It has its own configuration sub-section** (`"AuthCenter:Oidc"`, read with `LocalAuthCenter.GetSchemeSettings`). Its
  package declares the key with an [`IAuthCenterSchemeConfiguration`](IAuthCenterSchemeConfiguration.cs): **a sub-section
  that no installed package declares is a configuration error** (a configured family that silently does nothing is a
  misconfiguration).
- **It drives a login provider** (`ProviderName`): the scheme listing shows the family's `Schemes` instead of the
  provider name.
- **The account creation is the family's decision** (`AllowsAccountCreation`): the opener calls the optional
  `IAutoCreateAccountService` only for a scheme whose family allows it. Fail closed: a scheme without family (Basic,
  Weak) never creates an account, and no family does by default.

## Remote logins ([`AuthCenterOperationHandlers`](AuthCenterOperationHandlers.cs), [`IAuthCenterRemoteScheme`](IAuthCenterRemoteScheme.cs))

The endpoint executes the generic `IStartLoginCommand` and `IRemoteLoginCallbackCommand`, whatever the remote family,
with two operations handled here: the local Authentication Center keeps the **pending remote logins**
([`AuthCenterPendingStore`](AuthCenterPendingStore.cs): in memory, one use, 10 minutes, at most 10,000) and the family
only runs its protocol.

1. **`IStartRemoteLoginOperationCommand`**: the scheme must belong to a remote family, the endpoint must be able to
   receive remote logins with a callback that the family allows for the scheme, the `ReturnUrl` must be a relative path.
   The core chooses the state, the family returns the URL and its private data, and the pending login keeps them with the
   scheme, the callback, the hash of the endpoint's correlation secret, `RememberMe` and an immutable copy of the
   `UserData`.
2. **`ICompleteRemoteLoginOperationCommand`** (it carries the callback built by the endpoint): the pending login is
   consumed (one use), its expiry is checked, and the correlation presented by the endpoint must be the one of the start
   (**login CSRF**: only the caller that started a login can complete it). The family completes the login with the payload
   of its login provider, and the session is opened with the **user data of the start**: the callback never carries them.

The `Code` of the callback is `[Sensitive]`: from a remote, it travels encrypted for the Authentication Center.

## The commands from its remotes

Its remotes (CK.AppIdentity.Cris.AuthCenter.Remote) send it the operations of their endpoints and the commands it
handles, over the Cris channel. The identity of their users is established by
[CK.AppIdentity.Cris.Authentication](../CK.AppIdentity.Cris.Authentication/README.md), with what this package provides:

- **The caller party policy** ([`AuthCenterCallerPartyService`](AuthCenterCallerParties.cs)): its remotes that have its
  "AuthCenter" feature may act for any user up to `Normal` (a remote vouches for the users of its endpoints, a deferred
  command included); any other caller party is refused.
- **The user's proof** ([`AuthCenterProofVerifier`](AuthCenterCallerParties.cs)): a token of this Authentication Center,
  presented with the binding secret of its session, whose session is alive and is still the token's one (same binding,
  same actor: a logout, a revocation or an impersonation takes effect at once, not after the token's lifetime). The
  proved identity keeps its level: this is how a `Critical` command (an impersonation, a passkey registration) crosses a
  party boundary. An invalid proof is ignored: the remote then only vouches, at most at `Normal`.
- **The sensitive fields** ([`AuthCenterFieldDecryptor`](AuthCenterFieldDecryptor.cs)) are decrypted on reception, before
  the validation and the execution. A clear value is refused, and so is a sensitive value from a party that is not one of
  its remotes. The encryption keys ([`AuthCenterEncryptionKeys`](AuthCenterEncryptionKeys.cs)) are in the
  `LocalFileStore` ("AuthCenter/EncryptionKeys"), protected by the local party's data protector; the current one is
  published, signed, to its remotes (`IGetAuthCenterEncryptionKeyQCommand`,
  [`AuthCenterEncryptionKeyHandler`](AuthCenterEncryptionKeyHandler.cs)).

A compromised remote can act only for the users it vouches for, at most at `Normal`: the high-value actions are
`Critical` and need the user's live proof.

## The PartyActor identifiers ([`AuthCenterPartyActorIdsHandler`](AuthCenterPartyActorIdsHandler.cs))

The Authentication Center answers `IGetPartyActorIdsQCommand` for a calling remote that has its "AuthCenter" feature:
the `PartyActorId` of the caller and of its local party. They are set by the PartyActor registrar of
[CK.DB.AppIdentity](../CK.DB.AppIdentity/README.md), that an Authentication Center is expected to install: without it,
they are 0 (logged as a warning) and the remote keeps 0.
