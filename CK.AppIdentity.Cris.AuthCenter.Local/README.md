# CK.AppIdentity.Cris.AuthCenter.Local

The Local side of the [AuthCenter feature](../CK.AppIdentity.Cris.AuthCenter/README.md): **this application is the
Authentication Center** of its local parties (the root and its tenant domains). Its
[`LocalAuthCenterFeatureDriver`](LocalAuthCenterFeatureDriver.cs) adds a [`LocalAuthCenter`](LocalAuthCenter.cs) to every
local party that designates itself (`"AuthCenter": true` or a settings section on the local party); a local party that
designates a remote is a configuration error (an application has one role: a front references
CK.AppIdentity.Cris.AuthCenter.Remote).

The `LocalAuthCenter` holds the settings, the sessions and the signing of the tokens. A remote Authentication Center has
its own settings: a settings section on a remote is ignored (with a warning).

## Settings ([`AuthCenterOptions`](AuthCenterOptions.cs))

Read from the `"AuthCenter"` section of the local party (never inherited, static):

| Key | Default | |
|---|---|---|
| `SessionLifetime` | 1 day | The `Expires` of a login. The session slides: each refresh moves its end `SessionLifetime` later. |
| `CriticalLifetime` | 5 minutes | The `CriticalExpires` of a login at `Critical` level. |
| `TokenLifetime` | 10 minutes | The lifetime of a token (at most the session's). |
| `RefreshGraceWindow` | 1 minute | How long the previous secrets of a session are accepted, once, after a rotation (0 disables it, at most 5 minutes). See "Sessions". |

## Sessions ([`AuthCenterSessionStore`](AuthCenterSessionStore.cs))

The sessions are in the `LocalFileStore` of the local party: `AuthCenter/Sessions/{ActualActorId}/{SessionId}`, so all
the sessions of an actor are in one folder. A session holds the **hashes** of the endpoint secrets, never the secrets.
The session identifiers are random (16 bytes, base64url) and checked before being used as file names.

**Rotation and reuse detection.** Every refresh, impersonation and end of impersonation rotates the secrets. A
presented proof that matches neither the current secrets nor (below) the previous ones **revokes the session**: two
parties hold the same cookies.

**The grace window** (`RefreshGraceWindow`): the answer of a rotation can be lost (a dropped connection, a front's relay
that timed out while the Authentication Center completed). The caller then still has the previous secrets. They are
accepted **once**, within the window after the rotation, by the operations that rotate again (refresh, impersonation, end
of impersonation) and by the logout; the rotation then clears them. An operation that doesn't rotate (the Critical-session
check of a passkey registration) refuses them without revoking. If someone else used them (a thief within the window),
the legitimate caller's secrets become orphaned and its next refresh revokes the session: the reuse detection is delayed,
not lost. The session file keeps the previous hashes and the rotation time (version 2; a version 1 file has none).

**One operation at a time per session:** reading the session, checking the proof, rotating and saving are serialized per
session in the Authentication Center (`AuthCenterSessionStore.LockAsync`): two concurrent rotations cannot both match.

## Opening a session ([`AuthCenterSessionOpener`](AuthCenterSessionOpener.cs))

The `IAuthenticationSessionOpener` of a local Authentication Center. The login handlers call it
(see CK.Cris.Authentication). It runs the login sequence (the `ILoginProvider` of the scheme, the `ILoginValidator`s, the
account creation or binding of an unregistered user), then stores the session, lets the endpoint issue its secrets and
returns the signed token.

**The Basic and Weak login handlers are here temporarily** ([`AuthCenterLoginHandlers`](AuthCenterLoginHandlers.cs)).
A package that implements an authentication provider handles its login commands, so they belong to
CK.DB.User.UserPassword and CK.DB.Actor.WeakActor. But these packages are also used by the old authentication stack, and
a handler needs CK.Cris.Authentication, which defines the same `CK.Auth.CrisAuthenticationService` as the old CK.Cris.Auth
(CS0433 in the generated code of an old-stack application). **When the old stack is retired, these handlers go back to
their DB packages.** Both use the command as the payload (the "Basic" login provider is CK.DB.User.UserPassword's);
the Weak one never remembers the session. The `IWeakZoneLoginCommand` handler is in CK.DB.Zone.WeakActor.


## The other session commands ([`AuthCenterSessionService`](AuthCenterSessionService.cs))

They carry nothing: they act on **the current session**, the one whose proof the endpoint presents. The session key
(`"{ActualActorId}.{SessionId}"`, given to `IAuthenticationSessionEndpoint.Issue`) finds it, and the proof must match
**exactly**: the key and both secret hashes (compared in constant time). The key is not a secret.

| Command | |
|---|---|
| `IRefreshSessionCommand` | Reads the actors again (a disabled or removed actor cannot refresh), at most at `Normal` level (the `Critical` level requires a login), slides the session (it ends `SessionLifetime` after the refresh), rotates the secrets and issues a new token. The impersonation is kept. |
| `ILogoutSessionCommand` | Deletes the session (only when the proof matches: a key alone deletes nothing) and clears the endpoint secrets. |
| `IImpersonateCommand` | Requires the `Critical` level and an `IImpersonationService` that allows it (refused by default). Impersonating oneself is refused. |
| `IClearImpersonationCommand` | Always possible: it can only lower the privileges. |
| `IGetLoginSchemesQCommand` | The provider names of the login providers; the provider of a scheme family appears as the schemes of its family ("Oidc" as its configured `Oidc.<Suffix>` schemes). Not a session command. |

**A replayed secret revokes the session.** The secrets rotate at each refresh, so a refresh secret is used once: the
right key with other secrets means that the secrets have been stolen (or that two copies of the caller compete). The
session is deleted and the endpoint secrets are cleared. The legitimate caller then has to log in again.

**The purge of the expired sessions** runs every hour (`LocalAuthCenter.PurgePeriod`, from the first heartbeat) in the
background, never on the agent loop. No setting: every save writes the session file and a session never ends later
than `SessionLifetime` after it, so the files written before "now - SessionLifetime" are the candidates, and their
end is checked before they are deleted. An expired session that is presented is also deleted at once.

## Scheme families ([`IAuthCenterScheme`](IAuthCenterScheme.cs))

This package knows no login technology beyond the direct Basic and Weak commands (temporarily, see above): each family
of schemes is a package of its own ("Package First": a simple application references little). For concrete families
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

## Remote logins ([`AuthCenterRemoteLoginHandlers`](AuthCenterRemoteLoginHandlers.cs), [`IAuthCenterRemoteScheme`](IAuthCenterRemoteScheme.cs))

The generic `IStartLoginCommand` and `IRemoteLoginCallbackCommand` are handled here, whatever the remote family: a Cris
command has one handler, two remote families cannot both claim them. The local Authentication Center keeps the
**pending remote logins** ([`AuthCenterPendingStore`](AuthCenterPendingStore.cs): in memory, one use, 10 minutes, at
most 10,000) and the family only runs its protocol.

1. **`IStartLoginCommand`**: the scheme must belong to a remote family, the endpoint must be able to receive remote
   logins with a callback that the family allows for the scheme, the `ReturnUrl` must be a relative path. The core chooses
   the state, the family returns the URL and its private data, and the pending login keeps them with the scheme, the
   callback, the hash of the endpoint's correlation secret, `RememberMe` and an immutable copy of the `UserData`.
2. **`IRemoteLoginCallbackCommand`** (built by the endpoint's callback): the pending login is consumed (one use), its
   expiry is checked, and the correlation presented by the endpoint must be the one of the start (**login CSRF**: only the
   caller that started a login can complete it). The family completes the login with the payload of its login provider,
   and the session is opened with the **user data of the start**: the callback never carries them.

The `Code` of the callback is `[Sensitive]`: it is encrypted in place when relayed.

## The relayed commands ([`AuthCenterRelayHandler`](AuthCenterRelayHandler.cs))

The fronts (CK.AppIdentity.Cris.AuthCenter.Remote) relay the session commands and the `ICommandAuthCenter` commands over
the Cris channel. The protocol is in [CK.IO.AuthCenter](../CK.IO.AuthCenter).

**The session commands:**
- **Authorization without configuration:** only its remotes that have its "AuthCenter" feature (its fronts) can relay.
- It reads the bearer token again (the front is never trusted), validates the relayed command as an incoming command and
  executes it in its own endpoint ([`AuthCenterRelayDIContainerDefinition`](AuthCenterRelayDIContainerDefinition.cs)):
  the session endpoint is the relayed one (it presents what the front presented, its `Issue` uses the front's prepared
  hashes), the current local party is the Authentication Center, the caller is the front.

**The commands executed by the Authentication Center** (`ICommandAuthCenter`, CK.IO.Auth) are what a login point serves:
the actor's self-service on its own login methods (its passkeys, its password) and the login schemes
(`IGetLoginSchemesQCommand`). Never the administration: an Authentication Center is a login point, not an
administration point.

The Authentication Center never trusts the front for the identity:
- only its fronts can relay, and **only the `ICommandAuthCenter` commands** are executed (never a session command: they
  have their own relay). Anything else is refused and logged `SecurityCritical`;
- the identity is established again: the token is read with its keys, it must be presented with the binding secret of its
  session, and **its session must be alive and still the token's one** (same binding, same actor). A logout, a
  revocation or an impersonation takes effect at once for these commands, not after the token's lifetime. Anything else
  is the anonymous: the authentication parts of the command then fail its validation;
- the command is validated as an incoming command and executed in the relay endpoint, without session endpoint.

So a compromised front can act only for the callers that use it, while their sessions live.

**The sensitive fields** are decrypted before the validation and the execution, and a clear value is refused (see the
core package). The encryption keys ([`AuthCenterEncryptionKeys`](AuthCenterEncryptionKeys.cs)) are in the
`LocalFileStore` ("AuthCenter/EncryptionKeys"), protected by the local party's data protector; the current one is
published, signed, to the fronts (`IGetAuthCenterEncryptionKeyQCommand`).

## The PartyActor identifiers ([`AuthCenterPartyActorIdsHandler`](AuthCenterPartyActorIdsHandler.cs))

The Authentication Center answers `IGetPartyActorIdsQCommand` for a calling remote that has its "AuthCenter" feature:
the `PartyActorId` of the caller and of its local party. They are set by the PartyActor registrar of
[CK.DB.AppIdentity](../CK.DB.AppIdentity/README.md), that an Authentication Center is expected to install: without it,
they are 0 (logged as a warning) and the remote keeps 0.
