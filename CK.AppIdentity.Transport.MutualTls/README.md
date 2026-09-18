# Mutual TLS transport (`mtls:`)

The Zero Protocol inside a mutually authenticated TLS channel. Payloads are unreadable on the wire,
which is the whole point — and why this is a separate transport rather than a replacement for `tcp:`,
where readable packets are a deliberate operational requirement.

Register it and address a remote with the `mtls:` prefix:

```csharp
services.AddSingleton<MutualTlsTransportTypeService>();
services.AddSingleton<ITransportTypeService>( sp => sp.GetRequiredService<MutualTlsTransportTypeService>() );
```

```json
{
  "FullName": "Acme/$Gateway",
  "ListeningAddress": "mtls:0.0.0.0:37121",
  "Parties": [ { "PartyName": "$Device", "Address": "mtls:10.0.0.4:37121" } ]
}
```

The default port is **37121**, deliberately not `tcp:`'s 37120. The first bytes on the wire differ —
a TLS `ClientHello` against an InitialMessage — so a peer pointed at the wrong one fails to parse
rather than half-connecting, and one party can listen on both.

A client certificate is always required and always requested. There is no server-only mode.

## Where the certificates come from

Each party presents a certificate **issued by its own identity key**, carrying a freshly generated key
pair of its own (`LocalIdentityKey.CreateDerivedCertificate`). The identity private key signs it and
never leaves `CK.AppIdentity.KeyManagement`.

That is why the identity certificate is a CA limited to `pathLen 0`: it issues leaves and nothing
else, so no derived credential can itself become an issuer. A credential can be reissued or abandoned
without touching the identity that every remote has pinned.

Nothing needs configuring. There is no certificate file, no store, no CA to run.

## What authenticates the peer — and what does not

**Not the certificate.** These certificates chain to nothing either machine trusts, so a chain verdict
would carry no information; the handshake accepts any well-formed certificate on both sides. If that
sounds alarming, read the next paragraph before concluding anything.

**The binding is an attestation inside the signed handshake.** Each side states the SHA-256 of the
certificate it presented, inside the Zero Protocol transcript it signs with its identity key, and each
checks that statement against what TLS actually handed it. Anything terminating TLS between two peers
has to present a certificate of its own, and cannot make either peer sign a statement about a
certificate that peer never held. It may forward the signed bytes unchanged — that is exactly what
does not help it.

So the TLS channel and the authenticated identity are one lock, not two.

The known limit: TLS itself is unauthenticated here, so an active attacker can complete a handshake
with both sides and observe the Zero Protocol exchange before being rejected. Nothing confidential is
in there — names, instance ids, protocol lists, nonces, public keys — and no application payload flows
before the handshake completes. But it does reveal who is talking to whom, which certificate pinning
would deny at the TLS layer.

## Identifying a peer before it speaks

The listener also works out which of its parties is connecting, from the certificate alone, and the
incoming path holds that answer against the claimed name in the signed InitialMessage. A peer that
resolves to one party while claiming to be another is refused.

Because the credential is derived, its key matches no pinned identity; what names the party is the
**signature** on it. `IdentityIssuance` verifies that signature against the bare pinned
SubjectPublicKeyInfo — net8.0 offers no supported way to do this, so it reads the certificate's own
`SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }` encoding and checks the signature
directly. It is not a chain validator and does not pretend to be one; see its documentation.

A party whose identity is not trusted yet resolves to nothing. That is normal, not a rejection: with
no pinned key there is nothing to check a signature against, so first contact takes the same path a
`tcp:` connection takes and `AutoTrustKey` still works.

## Operational notes

- **The run-phase MAC is kept**, although TLS already provides integrity. It is bound to the
  AppIdentity session rather than to the channel, so it keeps meaning something if the channel is
  terminated somewhere in between.
- **The listener does not handshake on its accept loop.** A TLS handshake is a round trip; performing
  it inline would let one client that connects and says nothing stall every other accept. It also
  takes its admission slot *before* the handshake, and one timeout budget covers the TLS phase and
  the Zero Protocol phase together.
- **A listener is shared by address**, so it may serve parties belonging to several local parties. The
  certificate it presents is derived from the application's own identity. Under this design that
  certificate identifies nothing, so sharing is harmless — but it is a decision, not an accident.
- **`DefaultListeningAddress` is set**, so registering this service gives an mTLS listening address to
  any party that already has two or more configured listening addresses, on a port that may be
  firewalled or taken. A party with exactly one configured address is unaffected. Use
  `ListeningTypes` to be explicit.
