# Initial negotiation

A connection becomes usable only once the "0 Protocol" negotiation has authenticated both sides and agreed on the
protocols. The initiator side runs in the [`OutgoingConnectionBackTask`](OutgoingConnectionBackTask.cs), the listener
side in the [`IncomingConnectionBackTask`](IncomingConnectionBackTask.cs); the messages are written and read by
`ZeroProtocol` ([`ZeroProtocol.Negotiation.cs`](../ZeroProtocol.Negotiation.cs)).

Back tasks are not timers: the `TransportManager` heartbeat checks them, and kills the transport of a negotiation that
takes too long. An incoming negotiation has 2 seconds (`TransportManager.IncomingNegotiationTimeout`), counted from the
acceptance of the connection; an outgoing one has the remote's `OutgoingNegotiationTimeout` (15 seconds by default),
counted before the connection is opened.

## Exchanges

### 1. Initiator: the InitialMessage

| Field | |
|-------|---|
| Prefix | `CK-AppId` in ASCII. A listener that does not read it drops the connection. |
| ZeroProtocol version | Currently 0. |
| `CoreApplicationIdentity.InstanceId` | The instance of the calling process. |
| FullName | The full name of the initiator's local party. |
| Protocols | Count and full names ("Name.Version") of every registered protocol version. |
| Expected common protocol count | How many protocols the initiator needs. |
| CanAutoTrust | Whether the initiator will pin the listener's identity on first contact (`AutoTrustKey` is `Once` and nothing is pinned). |
| Ephemeral public key | The initiator's half of the ECDH key agreement of this connection. |
| MAC capabilities | The MAC algorithms this machine can run. |
| Certificate binding | The SHA-256 of the certificate the initiator presents on the transport (empty on `tcp:`). |
| Nonce | Its creation time and a random 64-bit value. |
| Identity block | See below. |

Every signed message ends with an **identity block**: the tail of the sender's key event log (at most 8 events), what the
sender pins for the receiver (a sequence and an event digest, or nothing), the sender's operational credential, and one
signature, by the credential's key, over the SHA-512 of everything before it.

### 2. Listener: the first answer

The listener finds the remote among the parties of its listener by the full name, applies the tail to what it pins for
it, verifies the credential against the key at the head of the tail and the signature with the credential's key, checks
the certificate binding against what the transport received, then the nonce (UTC creation time, clock offset within
`MaxClockOffset`, never seen before). When the transport already identified the peer (from its certificate), the
signed full name must be the same party.

Its answer is one of these (the first byte of the payload is the discriminator):

| Discriminator | Message | When |
|---------------|---------|------|
| 1 | FinalFailure | The signature or the nonce does not verify. One byte, unsigned. |
| 0 | RejectRemote | A configuration or trust issue: unknown caller, disallowed or unsupported transport, invalid clock offset, two initiators, an approval required on one side or both, or an identity conflict (the caller presented a log that does not extend what the listener pins for it). Unsigned when the caller is unknown or its transport is disallowed (the listener cannot choose a local party to sign with); signed otherwise. It carries the listener's `EnlistRemoteUrl` when the caller is unknown or does not trust the listener. |
| 2 | DowngradeProtocol | The caller's version is greater than the listener's: the caller may retry once with the version it names. |
| 6 | OffRemote | The remote is switched off here. Signed, with the reason. |
| 4 | MissingProtocols | One side does not support the protocols the other needs. Signed, with both lists. |
| 5 | EvictionDisallowed | The remote is already connected and its `DisallowEviction` is true. Signed. |
| 3 | AcceptedProtocols | Everything is fine. Signed. |

AcceptedProtocols carries the nonce, the clock offset computed by the listener and its current time, the chosen
protocols (one version each), the listener's ephemeral public key, the selected MAC algorithm and the listener's own MAC
capabilities, its certificate binding and its identity block. The listener has derived its session keys before sending
it.

When the listener requires a local approval, it waits for the initiator's **RequiredEnlistUrl** (discriminator 8): the
initiator's own `EnlistRemoteUrl` for the listener, signed with the initiator's operational key. The issue then appears
on both sides as a `PeeringIssue`.

### 3. Initiator: the final message

On AcceptedProtocols, the initiator verifies the nonce, the protocols, the signature against what it trusts for the
listener and the certificate binding. The MAC algorithm must be one it offered and the best one both sides can run. It
then derives its session keys and sends **FinalSuccess** (discriminator 7): the nonce, its clock offset and a signature by
its operational key. Anything wrong is answered by a FinalFailure.

On any other answer, the initiator raises the matching `PeeringIssue` when there is one (and switches the remote off when
it is switched off for good), then retries later.

The listener verifies the FinalSuccess against the initiator's operational key, and the connection replaces (evicts) the
remote's previous one, if any.

## The session keys

Both sides derive two directional keys with HKDF-SHA256 from the ECDH shared secret, salted with the nonce. The
transcript bound into the derivation holds both MAC capability sets, the selected algorithm, the negotiated version and
the two full names: if any of it was altered in flight, the two sides derive different keys and the first run-phase frame
fails its MAC.

The run phase starts when the receive loop starts, on both sides: from then on every frame carries its authentication
tag. The run-phase "0 Protocol" messages are the keep-alive (`Empty` and `EmptyAck`), the Goodbye (255, signed by the
operational key), and the key events of a party (254) and their request (253).
