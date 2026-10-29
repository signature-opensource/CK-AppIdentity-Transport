# CK.AppIdentity.KeyManagement

Handles the identity keys of the parties. This is what "who is this?" resolves to: every authentication decision of
the transport layer, and every application signature a party makes or checks, ends up here.

The design has no certificate authority to run or to trust. Each party owns its identity, proves it with a log of key
events, and its remotes pin that log. Keys rotate under a successor committed to beforehand, so stealing the key in use
is not enough to take an identity over.

## The feature

[`KeyManagementFeatureDriver`](KeyManagementFeatureDriver.cs) manages the "KeyManagement" feature, allowed by default
(see the [CK.AppIdentity features](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/Features/README.md)):

- every local party where it is allowed (the root application and its tenant domains) gets an
  [`ILocalKeys`](ILocalKeys.cs): its own identity, its private keys and what it signs;
- every remote of such a local party where it is allowed gets an [`IRemoteKeys`](IRemoteKeys.cs): what this local party
  pins of the remote, and the replay cache of the nonces it sent.

Both are an [`IPartyKeys`](IPartyKeys.cs), so `party.GetFeature<IPartyKeys>()` answers whichever the party is. The
driver requires an `IDataProtectionProvider` and an [`ICoreKeyStore`](ICoreKeyStore.cs). It exposes two events for
every local party at once: `AlertRaised` (see [Alerts](#alerts)) and `KeyEventAppended`, raised when the key event log of
a local party gains an event.

## An identity is a key event log

A [`KeyEvent`](KeyEvent.cs) reveals the ECDSA P-256 identity key of its sequence number and commits to the SHA-256 of the
next one (pre-rotation). An event is accepted after event `s` only when the key it reveals is the one event `s` committed
to, and when it is signed by that key: a thief holding the current key can sign with it, but cannot write the next event.

- **Recovery.** Every event carries the commitment to a recovery key, unchanged by ordinary rotations. Only a recovery
  event, revealing and signed by that key, can replace it, and it supersedes whatever ordinary events a verifier pinned:
  this is how an identity is taken back after its next key leaked.
- **Abandonment.** An event that commits to no next key ends the identity: nothing can follow it.
- **No party name inside.** The name is supplied by the reader and is part of what is signed, so an event of one party
  can never be accepted into the log of another.

[`KeyEventChain.Verify`](KeyEventChain.cs) checks a tail of events (at most `KeyEventChain.MaxEventTail`, 8) against the
pinned event and returns a [`KeyChainVerdict`](KeyEventChain.cs): `UpToDate`, `Advanced` (valid rotations), `Recovered`,
`Abandoned`, `Terminated`, `Rollback`, `TooFarBehind` (more rotations behind than a tail carries: an operator must
re-pin), `Duplicity` (two validly signed events at the pinned position: proof that a committed key leaked), `Unpinned`
(nothing pinned: the head is only self-asserted) or `Invalid`. It is pure: the caller applies the verdict.

## Local keys

The identity of a local party ([`ILocalKeys`](ILocalKeys.cs)) lives in its `LocalFileStore`, under `Keys`:

| File | Content |
|------|---------|
| `Kel/{Seq}.event` | The key event log. It is the single source of truth: an own log that does not verify stops the party. |
| `Current.cer` | The self-signed certificate of the current identity key (public, re-minted when missing or invalid). |
| `Identity.{Seq}.trust` | The head of the log, exactly the file a remote pins: an operator can copy it to a peer to pin it out of band. |
| `Alerts/{Id}.alert` | The unacknowledged [alerts](#alerts). |

The private keys are in the `ICoreKeyStore`, named by their sequence number: the current key is the head of the log,
the next key is head + 1. When a party starts without a log, it creates a new identity, which every remote has to
approve.

- **Rotation.** `Rotate()` replaces the current key by the committed next one and commits to a new next key: this is
  also how a key is revoked, by rotating early. The identity certificate is minted for twice `AllowedOfflineDays`, and a
  rotation is scheduled (at start and from the heartbeat) once it has less than `AllowedOfflineDays` plus one day left.
  When a scheduled rotation fails, the party keeps its key under a fresh certificate and raises a `RotationFailing`
  alert.
- **Recovery.** `Recover()` writes a recovery event (revealing the recovery key, given back from offline or taken from
  the key store) followed at once by an ordinary rotation to a fresh online key. Every remote that receives the tail
  drops whatever it had pinned since.
- **Decommission.** `Decommission()` writes an abandonment event, signed by the committed next key, and destroys the
  keys: the party then refuses to start until its `Keys` folder and key store are reset.
- **Operational credential.** The identity key does not sign the handshakes: it issues an
  [`OperationalCredential`](OperationalCredential.cs), a short-lived X.509 leaf whose own key signs them. It lives
  `OperationalKeyDays` (bounded by the identity's own expiry) and is renewed at half its life, so a stolen operational key
  dies on its own. `LocalIdentityState` (the `State` property) is the snapshot of the current key, its log tail and its
  credential: whatever goes on the wire comes from one snapshot.
- **Derived credentials.** [`LocalIdentityKey.CreateDerivedCertificate`](LocalIdentityKey.cs) issues an end-entity
  certificate, signed by the identity key, for a fresh key pair of its own. The identity certificate is a CA limited to
  `pathLen 0`, so a derived credential can never itself become an issuer. A caller that needs a key for some purpose asks
  for one to be issued: the identity private key is never exposed.
- **Data protection.** `Protector` is an `IDataProtector` dedicated to the local party, for small token-like data.

## Remote keys

What a local party trusts of a remote ([`IRemoteKeys`](IRemoteKeys.cs)) lives in the remote's `SharedFileStore`:

- **The pin** is the encoded event stored as `Identity.{Seq}.trust` (`TrustedEvent`, and `TrustedIdentity` the key it
  reveals). It moves forward only through rotations the remote committed to (`ApplyTail`), or by an operator
  (`SetTrustedIdentity`, which requires an event signed by the key it reveals). Two processes sharing the folder write
  different files and the highest sequence wins.
- **The history** (`KeyHistory/{Seq}.event`): the events the pin moved past, kept while what their keys issued can still
  be valid, so that a regular rotation does not end what the remote signed for the application. A recovery drops them.
- **The duplicity evidence** (`Duplicity/`, at most 16 files): the two conflicting events of a fork.
- **First use.** With `AutoTrustKey` set to `Once` and nothing pinned, `AdoptSelfAsserted` pins the head a remote
  presented. This is a trust-on-first-use decision, not a proof. There is deliberately no "always": over an existing pin,
  an unrelated identity is a takeover.
- **Replay protection.** `CheckNonce` checks that a handshake nonce has a UTC creation time within `MaxClockOffset` and
  has never been seen from this remote. The cache is per remote and per local party (`-Locals/{local full name}/Nonce.cache`),
  every accepted nonce is first journaled to disk (`Nonce.journal`), so a crash forgets nothing. It is bounded by time and,
  as a memory guard, by `IRemoteKeys.MaxNonceCacheEntries` (4096).

An operator who confirms a key that was not verified beforehand should compare its fingerprint out of band:
`IPublicKeyData.GetFingerprint()` (see [`PublicKeyFingerprint`](PublicKeyFingerprint.cs)) is a short Base32 rendering of
the SHA-256 of the key, made to be read out loud.

## Application signatures

`ILocalKeys.Sign( purpose, data, expiration )` signs application data (an authentication token, for instance) and
returns an [`ApplicationSignature`](ApplicationSignature.cs): one value that carries the signature and the application
credential that made it. The identity key never signs application data itself: it issues an application credential with
its own extended key usage, so an application signature can never pass for a handshake signature, nor the reverse.

- **Purpose.** What is signed is the purpose, the expiration and the data: a signature made for one purpose is refused for
  any other, and its expiration cannot be extended.
- **Expiration.** At most `MaxSignatureDays` ahead; the verifier checks it strictly, with no clock offset.
- **Validity.** A regular rotation has no effect on what was signed before it, a recovery condemns it, a decommission does
  not. A verifier refuses a credential that lives longer than its own `AllowedOfflineDays`.

Any party checks a signature with `IPartyKeys.Verify` or `IPartyKeys.Check`, whose [`SignatureVerdict`](SignatureVerdict.cs)
tells an `UnknownIssuer` (the signer rotated and this party has not seen its new key events yet: moving the pin may make
it valid) from a `Refused` signature.

## Alerts

An [`IdentityAlert`](IdentityAlert.cs) says that an identity is in doubt, even when everything keeps working. It is
persisted until `ILocalKeys.Acknowledge` is called, logged again at each start, deduplicated, and every log entry about
it carries the `IdentityAlert.LogTag` tag. The kinds:

| `IdentityAlertKind` | Raised when |
|---------------------|-------------|
| `IdentityTakenOver` | An authenticated remote pins this party at a sequence beyond its own log. |
| `IdentityForked` | An authenticated remote pins, at a sequence this party holds, an event that is not this party's. |
| `RemoteDuplicity` | A remote presented two validly signed events at the same sequence. |
| `NextKeyLost` | The next identity key is missing, or is not the committed one: the party can neither rotate nor be revoked. |
| `RotationFailing` | A scheduled rotation could not happen. |

The first two come from `ReportPinStatement`: what an authenticated remote states it pins for this party. The transport
layer reports these statements from its handshakes.

## Key custody

[`ICoreKeyStore`](ICoreKeyStore.cs) holds the private keys: they are created inside the store and used through an
`ECDsa` handle, never imported, so a store can make them non-exportable. The default implementation,
[`DefaultCoreKeyStore`](DefaultCoreKeyStore.cs), writes one file per key (`CoreKeys/{name}.key` in the local party's
`LocalFileStore`), its PKCS#8 content protected by DataProtection. This protects against a key file that leaks without
the key ring, not against a compromised host, and a warning says so at first use.

Another store replaces it by taking the `DefaultCoreKeyStore` as a constructor parameter (and may fall back to it). For a
store built on this interface that keeps the keys in hardware, see
[CK.AppIdentity.KeyManagement.Cng](../CK.AppIdentity.KeyManagement.Cng/README.md).

## Configuration

On a local party (read from its `"Local"` section only, never from a `"Defaults"`):

| Key | Default | |
|-----|---------|---|
| `AllowedOfflineDays` | 60 | How long this party or a remote can stay offline without losing their identities (7 to 3650). It drives the rotation period and bounds the credentials this party accepts. |
| `OperationalKeyDays` | 7 | Lifetime of the operational credential (1 to 31). |
| `MaxSignatureDays` | 7 | Longest expiration of an application signature (1 to `AllowedOfflineDays`). It must not exceed the `AllowedOfflineDays` of the parties that verify the signatures. |
| `RecoveryPublicKey` | none | The base64 SubjectPublicKeyInfo of a P-256 key generated and kept offline, read when an identity is created. Without it, the recovery key is created in the key store: it then helps only when the next key leaked on its own, not after a compromise of the host. |

On a remote (its own entry, otherwise the nearest `"Defaults"` above it, see
[the structural levels and the defaults](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Configuration/README.md#the-structural-levels-and-the-defaults)):

| Key | Default | |
|-----|---------|---|
| `AutoTrustKey` | `Never` | `Once` pins the identity the remote presents when nothing is pinned yet. |
| `MaxClockOffset` | `00:05:00` | The clock offset tolerated with the remote, between 1 and 20 minutes. |

Out-of-range values are clamped (or replaced by the default) with a warning.

## Requires

- [CK.AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/README.md): the
  parties, their features and their file stores.
- Microsoft.AspNetCore.DataProtection.Abstractions.
