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
The `"AuthCenter"` of the `"Local"` gives the role of the local party (the only designation key,
`"Local:AuthCenterParty"`, is for an Authentication Center reached without a channel):

| The local party | Its role | Its remotes that allow `"AuthCenterRemote"` |
|---|---|---|
| allows `"AuthCenter"` | It **is** its own Authentication Center (CK.AppIdentity.AuthCenter.Local). | They use it (they share its `CrisAuthCenter`): a `"Defaults"` that allows `"AuthCenterRemote"` lets all of them use it. |
| doesn't allow it | It relays its authentication to a remote Authentication Center (CK.AppIdentity.AuthCenter.Remote). | **The** remote that is its Authentication Center: at most one. Without such a remote, `"Local:AuthCenterParty"` designates an anchored Authentication Center reached without a channel (see [CK.AppIdentity.AuthCenter.Remote](../CK.AppIdentity.AuthCenter.Remote/README.md)). |

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

A local Authentication Center hosts the `"AuthCenter"` route (`AuthCenterFeature.RouteName`, its target is its full
name): every party of the System has a path to it, whatever its channels. A party that anchors the Authentication
Center without a channel to it gets its key events along this route (the `AnchoredKeyDirectory` of CK.AppIdentity.Cris).

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
- **The session party:** the full name of the party that opened the session (the one that serves the user's client
  application, see `AuthCenterTokenContent.SessionParty`). Only this party may present the token at the `Critical` level
  to another party (see "The user's proof").
- **The authentication cannot outlive the token:** its dates are clamped to the token expiration.
- **Revocation:** tokens are verified locally, without the session store, so a revoked session stays usable until its
  token expires: at most `TokenLifetime`. The client refreshes its token with `IRefreshSessionCommand`.
- The credential of the signature is embedded in every token (simpler; the "credential sent once" option stays open).

The tokens are signed by the Local side (`LocalAuthCenter.CreateToken`).

**The tokens of a remote Authentication Center** (on a remote of it) are verified with the pinned keys of the Authentication
Center. Their audience is the Authentication Center party. After a key rotation, the Authentication Center pushes its new
key events to its connected remotes (the transport does it, see CK.AppIdentity.TransportLayer). A remote that missed them
uses `ReadTokenAsync`: when a token is refused because its issuer is not known (`SignatureVerdict.UnknownIssuer`), the key
events are requested (at most `CrisAuthCenter.KeyEventsTimeout`, 2 seconds) and the token is read again, once. Anyone
can send a signature of an unknown issuer (a token, a System list): the concurrent requests share one, and none starts
within a second of the end of the previous one (`CheckWithKeyEventsAsync` follows the same rule).

## The user's proof

A command that carries an identity is received with the identity vouched for by its caller party, at most at `Normal`
(see [CK.AppIdentity.Cris.Authentication](../CK.AppIdentity.Cris.Authentication/README.md)). The user's proof lets it keep
its level, `Critical` included, across any number of parties of the System:

- **A party relays only a proof it verified.** So a proof that doesn't verify is evidence against the party that sent it
  (the channel authenticates it): a `SecurityCritical` warning names it. The local reading
  (`CrisAuthCenter.ReadProofAsync`: the token with the Authentication Center's keys, and its binding) needs no round trip.
- **Sending it** ([`AuthCenterProofContributor`](AuthCenterProofContributor.cs)): in an interactive request, the token
  **accepted** by the endpoint (`IAuthenticationSessionEndpoint.AcceptedToken`: a token it refused, or couldn't read, is
  never sent) and the binding secret hash presented with it are put in the envelope (`IAuthenticationCallEnvelope`) of
  every command that carries an identity, sent to any remote **inside the System** (the same domain and environment). A
  proof is a bearer credential: it never leaves the System. A deferred execution has no presented proof: the caller
  party alone vouches, at most at `Normal`.
- **Through hops, the session party seals the command** ([`RoutedCommandSeal`](RoutedCommandSeal.cs), by the
  [`AuthCenterRoutedCommandSeal`](AuthCenterRoutedCommandSeal.cs), the `ICrisRoutedCommandSeal` of the routed commands): the proof of a
  routed command is sent with a seal, the signature by the session party (the origin of the route) of a header (the
  destination, the digest of the token, the time, a nonce) and of the digest of the exact bytes of the command. The
  Authentication Center verifies it without the command: for its own routed commands, or asked by its remote that is
  the destination (`IVerifyCallerProofCommand`: the asking party must be the destination). A seal is used once (its
  nonce is kept for its 5 minutes lifetime, in a journal of the local store of the Authentication Center flushed to the
  disk before the seal is accepted: a restart forgets nothing). A routed proof without a valid seal, or routed from another origin than the
  session party, is ignored (a `SecurityCritical` warning): the hops can't alter the command, re-target it, nor use the
  proof for another command.
- **Encrypted for its destination** when its key is known (the origin's `IPartyEncryptionKeyDirectory`): the proof and
  the command are encrypted with the header as associated data, then signed (encrypt, then sign). The envelope carries
  the seal, not the proof: a hop sees neither the command nor the proof. The destination decrypts it with its
  party's encryption keys, puts the proof back into the envelope and reads the command from the decrypted bytes. Without
  a verified key for the destination, the command is not sent (a `SecurityCritical` warning): a command that carries a
  proof never travels in clear, so a hop that withholds the key of the destination gets nothing from it.
- **The result of an encrypted command is encrypted for the origin**, with the response key of the encryption (only the
  origin and the destination hold it): the hops relay a sealed result.
- **Forwarding it** ([`AuthCenterProofForwardFilter`](AuthCenterProofForwardFilter.cs)): a party that forwards a routed
  command reads its proof first. A proof that doesn't verify is removed (and logged against the sender); a party without
  Authentication Center can't read it and removes it: the routed command arrives without proof.
- **Only the session party presents it at the `Critical` level:** a proof sent by another party than the token's
  session party gives the proved identity capped at `Normal`. A party that received the proof (a backend, a hop) can't
  reuse it at the `Critical` level toward a third party. Received directly, such a proof is a `SecurityCritical` warning
  (an honest party relays only the token presented to its own endpoint).
- **Verifying it** ([`AuthCenterProofVerifier`](AuthCenterProofVerifier.cs)): the receiving local party reads it (a
  failure is evidence against the sender), then asks its [`IAuthCenterProofChecker`](IAuthCenterProofChecker.cs) for the
  liveness (a session that ended is not evidence: a logout may happen while a command travels). The token must be valid, its session alive and still the
  token's one (the same binding, the same actor: a logout, a revocation or an impersonation takes effect at once, not
  after the token's lifetime). The Authentication Center itself (`LocalAuthCenter`) checks its session store; any of its
  remotes (`RemoteAuthCenter`) reads the token with the pinned keys, then asks the Authentication Center for the liveness
  (`IVerifyCallerProofCommand`, internal, handled by `VerifyCallerProofHandler`). The answer is the identity stated by the
  Authentication Center: the one case where an `IAuthenticationInfoPoco` becomes a trusted authentication, because it is
  the Authentication Center's own statement, received from it over the channel. It fails closed: an unreachable
  Authentication Center or a refused proof gives no proved identity (the caller party then only vouches).

So any party of the System can relay a proof, and any local party that has an Authentication Center can verify it: a
`Critical` command (an impersonation, a passkey registration) executes wherever its handler is.

## The key directory ([`IPartyEncryptionKeyDirectory`](IPartyEncryptionKeyDirectory.cs))

A party encrypts for another one with the encryption key it publishes in its description (CK.AppIdentity.KeyManagement's
`PartyEncryption`). For a party that is not one of its remotes, the key would come by an untrusted path: the
Authentication Center vouches for it. It has pinned the keys of its remotes, and its remotes hold its keys.
- **On the Authentication Center** (`LocalAuthCenter`): the key of one of its remotes is the one in its description,
  verified with its pinned keys (its key events are requested once when the signer is unknown); its own key is its
  party's.
- **On a remote** (`RemoteAuthCenter`): the Authentication Center's key is the one in its description; the key of
  another party is asked to the Authentication Center (`IGetRemoteEncryptionKeyQCommand`, handled by
  `PartyEncryptionKeyDirectoryHandler` for its remotes only). It answers with a statement it signs
  ([`PartyEncryptionKeyStatement`](IPartyEncryptionKeyDirectory.cs): the full name of the party and its key, until the
  end of use of the key), verified like a token and cached until the key ends.

## The System list ([`SystemList`](SystemList.cs), [`AuthCenterSystemList`](AuthCenterSystemList.cs))

The Authentication Center states, for every party of its System, in one signed list: the revoked identities, and the
hosts authorized for the routes.

### The revocation

The Authentication Center revokes the identity of a party System-wide: `IRevokePartyCommand` (Critical, the operator's
live proof; who may revoke is decided by the application, a validator of the command), handled by the
`RevokePartyHandler` of CK.AppIdentity.AuthCenter.Local. What is revoked is the identity of a key event log (the digest
of its inception, given or read from the pin of the remote), refused forever once revoked; the entry also bans the
full name in the routed commands and the routes until it is readmitted (`IReadmitPartyNameCommand`, Critical too: the
party incepted again and comes back by a new enlistment or a new anchor, its revoked identities stay refused). A revoked
party is no more an authorized host of any route.

### The route hosts

A route is announced, not proven (see the routes of CK.AppIdentity.TransportLayer): the Authentication Center states who
may host a route, and every party that has it accepts a route only toward an authorized host of its name, with the
authorized target ([`AuthCenterRouteHostAuthority`](AuthCenterRouteHostAuthority.cs), the `IRouteHostAuthority` of the
transport: `AuthCenterSystemList.RouteHosts`). A name can have several hosts.

- **The "AuthCenter" route is implicit:** it is authorized toward the party's Authentication Center (its full name is
  known), without entry in the list: the list itself is pulled along it. Before any list, it is the only authorized route.
- **Who authorizes** (CK.AppIdentity.AuthCenter.Local): the `"RouteHosts"` of the center's `"AuthCenter"` section (the
  hosts known at deployment), the Critical `IAuthorizeRouteHostCommand` and `IRemoveRouteHostCommand` of an operator, and
  the approval of a party (CK.AppIdentity.AuthCenter.Enlistment: the routes the operator approves with it). The roles a
  party announces are not trusted for this: a party announces them itself.
- **The target follows the authorized host:** the center reads it in the host's description when it sees it (the
  center itself, or one of its remotes: `AuthCenterSystemList.FindAnnouncedTarget`) and signs a new list when it
  changes; a configured target is fixed.

### The list

- **The list:** the revoked identities, the route hosts, a sequence number and a time, signed by the Authentication
  Center (`SystemList.Purpose`). It is signed again (the next sequence number) when its signature reaches the middle of
  its life (checked every hour): a signature lasts at most `MaxSignatureDays`. The center changes it with
  `AuthCenterSystemList.UpdateAsync`: the updates are serialized (each one sees the list of the previous one), and the
  route hosts of a banned name are dropped from every new list.
- **Every party that has an Authentication Center** (local, remote, or anchored without channel) holds the newest list
  it verified (`AuthCenterSystemList`, a feature of the local party), in its local store. It applies it to its keys
  (the revoked remotes are cut, see CK.AppIdentity.TransportLayer) and to its routes (computed again when the route
  hosts change). At start, the stored list is verified again with the keys of the Authentication Center (it may have
  been replaced or re-incepted): a list it didn't sign is ignored, a list signed by a key not known yet is verified with
  its key events by the first heartbeat.

- **The distribution:** the list is sent on every channel that becomes available, and relayed to the other remotes of
  the System when a newer one is adopted (`ISystemListCommand`, internal and endpoint-only). A list is adopted when
  its sequence number is greater and its signature is the Authentication Center's (verified with its pinned or
  anchored keys): a hop can withhold a list, not forge one. A party without Authentication Center ignores it (its
  operator cuts its remotes).
- **The freshness:** a hop can withhold a newer list. Besides the relay by every channel, a party that is not the
  Authentication Center asks it its current list every hour (`IGetSystemListQCommand`, on the channel or along the
  `"AuthCenter"` route): to withhold, a hop must also block that, and an unreachable center is visible. A list whose
  signature expired (the center signs it again before) raises a `SecurityCritical` alarm: nothing newer reached the
  party (`AuthCenterSystemList.CheckStaleness`). A token that would state the sequence of the list is not done.

## The encryption of the sensitive fields ([`AuthCenterFieldEncryption`](AuthCenterFieldEncryption.cs))

The sensitive fields ([Sensitive] strings, like the Basic login password) of the commands that a remote sends to its
Authentication Center are **encrypted** by the remote (in a copy of the command, Remote side) for the Authentication
Center (Local side), so a `tcp:` channel stays acceptable:
- With the encryption key of the Authentication Center's party: the one it publishes in its description
  (`PartyDescription.EncryptionKey`, see CK.AppIdentity.KeyManagement's `PartyEncryption`: HPKE-like, ephemeral ECDH
  P-256, HKDF-SHA256, AES-256-GCM). A value becomes `"ckenc1:..."`. The sent command carries the ciphertext, never the
  clear value.
- The associated data binds a ciphertext to the Authentication Center, the remote, the command type, the property and
  its creation time: it cannot be moved to another field, command or remote, and one older than 5 minutes is refused.
- The Authentication Center decrypts before validating and executing, and **refuses a clear value**.
- The keys are the party's (CK.AppIdentity.KeyManagement): one published for a day, the next one 10 minutes before its
  end, the previous one still decrypts for 10 more minutes. A remote reads the current one in the Authentication
  Center's description, verifies its signature by the Authentication Center (with the same safety net as the tokens)
  and caches it until it changes or its signature expires.

