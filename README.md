# CK-AppIdentity-Transport

Communication between the parties modeled by [CK-AppIdentity](../CK-AppIdentity): parties find each
other, authenticate each other, and exchange messages over a pluggable transport.

The identity model itself — the application, its remotes, tenant domains, features and their
configuration — lives in CK-AppIdentity. This repository adds the wire.

## CK.AppIdentity.KeyManagement
The identity keys. Each local party owns ECDSA P-256 keys, stored and rotated on the file system, and
pins one public key per remote it trusts. This is what "who is this?" resolves to, and every
authentication decision in the transport layer ends up here.

## CK.AppIdentity.TransportLayer
The transport itself: listeners, connections, the "0 Protocol" handshake that authenticates both
parties, per-frame integrity afterwards, and the message framing channels are built on.

Read [its README](CK.AppIdentity.TransportLayer/README.md) before building on it — in particular
[the security model](CK.AppIdentity.TransportLayer/README.md#security-model), which says what is
protected and what deliberately is not. Messages are authenticated; **payloads are not encrypted**,
because readable packets on the wire are a requirement for deployments that audit their own traffic.

## CK.AppIdentity.BlobChannel
A channel that carries opaque `byte[]` between two parties. More a worked example of a channel than a
useful one, and the shortest path to seeing how a protocol plugs in.

## CK.AppIdentity.Cris
A channel that carries [CK-Cris](../CK-Cris) commands and their results between parties.
