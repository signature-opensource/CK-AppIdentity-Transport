# CK-AppIdentity-Transport

Communication between the parties modeled by [CK-AppIdentity](../CK-AppIdentity): parties find each
other, authenticate each other, and exchange messages over a pluggable transport.

The identity model itself — the application, its remotes, tenant domains, features and their
configuration — lives in CK-AppIdentity. This repository adds the wire.

## CK.AppIdentity.KeyManagement
Handles the Party identity keys. Each local party owns ECDSA P-256 keys, stored and rotated on the file system, and
pins one public key per remote it trusts. This is what "who is this?" resolves to, and every
authentication decision in the transport layer ends up here.

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

## CK.AppIdentity.TransportLayer.Testing
Test helpers shared by the test projects, including the adversarial peer — an independent
implementation of the wire format used to drive real parties with messages the production code would
never produce. Not a published package; it exists so that a second, divergent copy of the harness does
not appear.

## CK.AppIdentity.BlobChannel
A channel that carries opaque `byte[]` between two parties. More a worked example of a channel than a
useful one, and the shortest path to seeing how a protocol plugs in.

## CK.AppIdentity.Cris
A channel that carries [CK-Cris](../CK-Cris) commands and their results between parties.
