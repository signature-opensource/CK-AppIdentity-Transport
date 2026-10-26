# CK-AppIdentity-Transport

Communication between the parties modeled by [CK-AppIdentity](../CK-AppIdentity): parties find each
other, authenticate each other, and exchange messages over a pluggable transport.

The identity model itself — the application, its remotes, tenant domains, features and their
configuration — lives in CK-AppIdentity. This repository adds the wire.

## Security at a glance

Every connection between two parties is mutually authenticated with pinned public keys, and every frame
after the handshake is protected against tampering, injection, replay and reordering. There is no
certificate authority to run or to trust. Confidentiality is chosen per remote: `tcp:` keeps payloads
readable on purpose, so that deployments can audit their own traffic; `mtls:` encrypts them.

| Property | `tcp:` (default port 37120) | `mtls:` (default port 37121) |
|---|---|---|
| Mutual authentication | Signed handshake against pinned keys | The same handshake, bound to the TLS certificates |
| Integrity of every frame | 128-bit MAC per frame (AES-GMAC or HMAC-SHA256) | TLS, plus the same per-frame MAC |
| Confidentiality of payloads | **None, by design** | TLS 1.2 / 1.3 |
| A relay or TLS-terminating middlebox | Fails: the session keys come from the handshake | Fails: each side signs the hash of the certificate it presented |
| Certificates to manage | None | None: derived from each party's identity key |
| Visible to an observer | Who talks to whom, when, how much, and the payloads | Who talks to whom, when, how much |

Both run side by side; `ListeningTypes` restricts a party to the encrypted one. What each layer protects,
and what it deliberately does not, is detailed in
[the transport security model](CK.AppIdentity.TransportLayer/README.md#security-model),
[the mTLS transport](CK.AppIdentity.Transport.MutualTls/README.md) and
[CK.AppIdentity.KeyManagement](#ckappidentitykeymanagement) below.

### Design lineage

None of the mechanisms is new; the design combines proven ones without a certificate authority.

| Stack | What this design shares with it | Where it differs |
|---|---|---|
| [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) with client certificates | Mutual authentication, ephemeral ECDH, per-record integrity | No CA: identities are pinned keys. The identity survives a TLS-terminating middlebox (certificate binding inside the signed handshake). |
| [SSH](https://www.rfc-editor.org/rfc/rfc4251#section-4.1) | A local database of pinned host keys, optional acceptance of an unknown key on first connection | First-use trust is off by default (`AutoTrustKey.Never`) and is recorded as *self-asserted*, never *trusted*. Keys rotate under a pre-committed successor. |
| [WireGuard](https://www.wireguard.com/protocol/) (Noise IK) | Statically known peer keys, a fresh ephemeral key exchange per session | ECDSA / ECDH P-256 instead of Curve25519. Encryption is a per-link choice, not always on. |
| [KERI](https://arxiv.org/abs/1907.02143) (Key Event Receipt Infrastructure) | A chained [key event log](https://identity.foundation/keri/docs/Glossary.html), pre-rotation, a recovery key, [duplicity](https://identity.foundation/keri/docs/Glossary.html) as proof of compromise, "first seen" | Pinning between known parties: no witnesses or watchers network. |
| [SPIFFE / SPIRE](https://spiffe.io/docs/latest/spiffe-about/overview/) | Short-lived credentials certified by a longer-lived identity | No central issuing server: each party certifies its own operational keys. |
| [TLS 1.3 integrity-only suites (RFC 9150)](https://www.rfc-editor.org/rfc/rfc9150), [IPsec ESP with NULL encryption (RFC 2410)](https://www.rfc-editor.org/rfc/rfc2410) | Authenticated but readable traffic | Integrity-only is what `tcp:` does; `mtls:` adds encryption on the same identities. |

## CK.AppIdentity.KeyManagement
Handles the identity keys of the parties. This is what "who is this?" resolves to, and every authentication
decision in the transport layer ends up here.

- **An identity is a key event log.** Each local party owns ECDSA P-256 identity keys. Every event reveals the
  current key and commits to the hash of the next one (pre-rotation): a rotation is accepted only when it
  reveals the committed key and is signed by it, so a thief holding the current key cannot take the
  identity over. Every event also commits to an offline **recovery key**, the only one that can take back an
  identity rotated during a compromise.
- **Remotes are pinned by event.** A party pins the last verified event of each remote (a `.trust` file, that
  an operator can also copy out of band). Two different events at one position are proof of compromise and
  raise an alert; a party also learns, from a peer's refusal, that someone else rotated its identity.
- **The identity key signs rarely.** It certifies short-lived **operational keys** (7 days by default, 31 at
  most) that sign the handshakes, and application credentials (`ApplicationSignature`) for application
  data such as authentication tokens. Each use has its own purpose: one signature can never pass for another.
- **Custody is pluggable** (`ICoreKeyStore`): keys are created inside the store and used through a handle,
  never imported. The default store protects key files with the DataProtection key ring, which guards
  against a leaked file, not a compromised host.

## CK.AppIdentity.KeyManagement.Cng
An `ICoreKeyStore` that keeps the identity keys in a Windows CNG provider: the TPM by default, or an HSM or a
smart card provider. Keys are not exportable and every signature is made by the provider, so a copied,
backed-up or stolen host gives up no key. Unless fallback is explicitly allowed, an unusable provider stops
the party from starting rather than silently falling back to file keys.

## CK.AppIdentity.TransportLayer
The transport itself: listeners, connections, the "0 Protocol" handshake that authenticates both
parties, per-frame integrity afterwards, and the message framing channels are built on.

Read [its README](CK.AppIdentity.TransportLayer/README.md) before building on it — in particular
[the security model](CK.AppIdentity.TransportLayer/README.md#security-model), which says what is
protected and what deliberately is not. Messages are authenticated; **payloads are not encrypted**,
because readable packets on the wire are a requirement for deployments that audit their own traffic.

## CK.AppIdentity.Transport.MutualTls
The `mtls:` transport: the same handshake and framing inside a mutually authenticated TLS channel, for
deployments that need payloads unreadable on the wire. It coexists with `tcp:` and is selected per
remote by address, because the two requirements — audit every packet, and let nobody read them — are
genuinely opposed and the choice belongs to whoever configures the remote.

Certificates are issued by each party's own identity key and need no configuration at all. See
[its README](CK.AppIdentity.Transport.MutualTls/README.md), in particular what authenticates the peer:
it is not the certificate.

## CK.AppIdentity.BlobChannel
A channel that carries opaque `byte[]` between two parties. More a worked example of a channel than a
useful one, and the shortest path to seeing how a protocol plugs in.

## CK.AppIdentity.Cris
A channel that carries [CK-Cris](../CK-Cris) commands and their results between parties.

## The Authentication Center
The "AuthCenter" feature: the party that centralizes the authentication of a local party (the application or
one of its tenant domains). It is a singleton within its domain, so it comes in two sides and **an application
has one role**, given by the package it references:

- [CK.AppIdentity.Cris.AuthCenter](CK.AppIdentity.Cris.AuthCenter/README.md): the core shared by both sides,
  the designation of the Authentication Center and the reading of its tokens.
- [CK.AppIdentity.Cris.AuthCenter.Local](CK.AppIdentity.Cris.AuthCenter.Local/README.md): this application
  **is** the Authentication Center: settings, sessions, the signing of the tokens, the login handlers, the
  handling of what its fronts relay.
- [CK.AppIdentity.Cris.AuthCenter.Remote](CK.AppIdentity.Cris.AuthCenter.Remote/README.md): this application
  is a **front**: it relays the session commands to its remote Authentication Center, with their sensitive
  fields encrypted for it (so a password never crosses a `tcp:` link in clear).
- [CK.AppIdentity.Cris.AuthCenter.Oidc](CK.AppIdentity.Cris.AuthCenter.Oidc/README.md) and
  [CK.AppIdentity.Cris.AuthCenter.Passkey](CK.AppIdentity.Cris.AuthCenter.Passkey/README.md): the OpenID
  Connect and passkey (WebAuthn) logins of a local Authentication Center.
- [CK.IO.AuthCenter](CK.IO.AuthCenter/README.md): the relay protocol between the fronts and their
  Authentication Center.

## CK.DB.AppIdentity
The [PartyActor](CK.DB.AppIdentity/README.md): an actor of the CK-DB model that represents a party, so that
parties can be members of groups like any other actor.

## Testing helpers
- **CK.Testing.AppIdentity.TransportLayer**, shared by the test projects, includes the adversarial peer — an
  independent implementation of the wire format used to drive real parties with messages the production
  code would never produce. It exists so that a second, divergent copy of the harness does not appear.
- **CK.Testing.AppIdentity.Cris** runs real applications that talk over a Cris channel.
