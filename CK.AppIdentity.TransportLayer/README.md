# Transport Layer

## Configuration keys

`IRemoteParty.Address` is the only modeled property: it can only be defined on a RemoteParty and is optional.
When not specified, then the Remote is Client: we must act as a Server, meaning that we must listen to
incoming connections until the Remote establishes the connection. When listening to incoming connections, a
single local end point can handle connections from more than one RemoteParty: the `ListeningAddress` is a
configuration property that can be defined once, at the root level (ApplicationIdentityService), but nothing
prevents this `ListeningAddress` to be defined at any configuration level: they are combined. This enables
a dedicated listening address for a Domain or even for a specific Remote.

An `Address` or a `ListeningAddress` are mere strings: their exact syntax depends on the type of Transport that
must be used. This type must be specified (there is no default) with the standard URI protocol syntax: 'tcp:', 'quic:', 'pipe:', etc.

A `ListeningAddress` property at one level can be a string, a comma separated string or an array of strings,
but when more than one address is specified, there must be only one address per type of Transport. This is valid
`"ListeningAddress": [ "tcp:127.0.0.1:358", "pipe:TheNamedPipe" ]`.

When a `IRemoteParty.Address` is not specified, a third and last property can be used to choose which type of
transport listener must be used: the `ListeningTypes`:
  - It can be a simple string: 'all' to allow all the  `ListeningAddress` defined above, or one of the types (like 'tcp').
  - A comma separated string or an array of strings that are the transport type names to use.
This `ListeningTypes` property defaults to 'all': the remote can freely choose the transport type to use.

## TransportMessage
A [`TransportMessage`](Message/TransportMessage.cs) is a `ReadOnlySequence<byte>` with a prefixed length and a Protocol number.
The message is `IDisposable`: it holds its memory buffers that are pooled array of bytes. Messages can only be created
by methods of the [`IncomingMessageFactory`](Message/IncomingMessageFactory.cs) or [`OutgoingMessageFactory`](Message/OutgoingMessageFactory.cs).


## Message Prefix: Protocol and Length

All messages exchanged by the Transport layer are prefixed by the message's protocol and length.
- The prefix starts with a first byte: `|L0|L1|CD|R0|R1|P0|P1|P2|`.
  - The 2 MSB (L0-L1) gives us the number of bytes of the message length:
    - `00` 1 byte, the message length is between 0 and 255 bytes.
    - `01` 2 bytes, the message length is between 256 and 65535 bytes.
    - `10` 3 bytes, the message length is between 65536 and 16 777 215 bytes.
    - `11` 4 bytes, the message length is between 16 777 216 and 2 147 483 648 bytes (2 Gib).
  - The `CD` bit is the "Control vs. Data" bit. This is a convenient bit that can be used by protocols
    as a one bit discriminator, typically between a regular data message and one (or more) control message.
  - `R0` and `R1` bit are reserved for future use.
  - P0-P2 bits is the Protocol, a number between 0 and 7. This number defines the "type" of the
  message: the writer or serializer that has been used to write the payload and the reader or "deserializer"
  that must be used to read it back.
- Then comes the message length itself (1 to 4 bytes)
- Then the message payload itself.

At a higher level ["Protocols"](MessageProtocol.cs) are identified by a string (its unique name).
A protocol defines how the message is encoded and how they are exchanged: by merging these 2 concepts here,
we greatly simplify the implementation and the understandability of the Transport layer. The protocol simply
defines the encoding it uses.

The `"0 Protocol"` protocol name is reserved: this is the protocol of CK.AppIdentity.TransportLayer itself that handles
special messages used to negotiate, accept, reject incoming parties and outgoing connections.
This lets 7 possible protocols. This may seem a limitation however this limit applies to a Remote party pair: there
can be any number of possible protocols in an application, among them 2 parties that start to interact initially
negotiate the ones they can and want to use. Any Transport between 2 parties can support up to 7 different protocols.

The final length of a message on the wire is between 2 bytes (the special Empty message, see below) and 2 Gib.
A minimal 1 byte message requires 3 bytes (in any of the 7 available protocols). 

Two special public singletons TransportMessage exist (tied to the "0 Protocol").
They never cross a frontier, they can only be used locally on a party:
- The `TransportMessage.Invalid` is the "invalid" message, used when an invalid message is received.
- The `TransportMessage.Canceled` is a second "invalid" message, that is used to signal a canceled read operation.

Internally, 2 other special "0 Protocol" messages exist: `TransportMessage.Empty` and `TransportMessage.EmptyAck`.
They are valid messages that are exchanged to implement the KeepAlive functionality.
Their length on the wire is 2 bytes and they are the shortest messages that exist. Regular protocols
(other than the "0 Protocol") are not allowed to send empty messages.

## Connected or not connected?
Even if CK.AppIdentity is designed to work with connected remotes, the availability of a connection between two parties is
highly instable. One major goal of this library is to be easy to use and instability brings a lot of complexities.
To minimize the impact, numerous design choices have been made but the most important one is that sent messages are
internally queued and that temporary disconnection are transparently handled.

The [`TransportFeature`](TransportFeature.cs) exposes a `Task ReadyTask { get; }` that is completed when a first connection has been successfully
established with the remote. This task can be awaited (or its [`Task.IsCompleted`](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task.iscompleted)
status can be checked) before sending any data to the remote.
If the connection is lost, queued data are transmitted as soon as a new connection is available.
Obviously, pending messages cannot be collected _ad infitum_. The transport feature exposes a simplified "level of pressure"
with the ConnectionAvailability enumeration. This should be used before sending any data to a remote.

| Value | Name       | Description  |
|-------|------------|--------------|
|0      | None       | No connection at all. This is the initial state but may be restored (along with a new pending `ReadyTask`) when a long disconnection occurs.  |
|1      | DangerZone | Connected, but no longer answering: a keep-alive probe has gone unanswered. Any traffic from the remote clears it. |
|2      | Low        | A connection was lost and a reconnection is under way.  |
|3      | Connected  | The remote is connected.  |

A connection can die without either side saying so — the peer loses power, a NAT table entry
expires, a cable goes. Nothing notices on its own: reads never complete, and writes keep succeeding
into the kernel buffer. So a party that has received nothing for `KeepAliveIdleTime` asks the remote
whether it is still there, and a run of unanswered probes condemns the connection. `DangerZone` is
the warning in between — still connected, no longer answering — and is what an application should
watch to stop feeding a link that is about to go.

The probe and its acknowledgment are "0 Protocol" messages, so during the run phase they carry a MAC
like any other frame: an attacker who can inject bytes cannot forge an acknowledgment to hold a dead
link open.

Intended but **not yet implemented**: deriving the level from the sender queue's load as well, so
that a remote which is connected yet unable to keep up degrades before the queue fills. The sketch
below is that design, not current behaviour — today only the keep-alive and the connection state move
this value.

```
   0      15%   25%   35%        50%     65%   75%              100%
   +-------+-----+-----+----------+-------+-----+----------------+     
>> Connected           Low                      DangerZone
<< Connected     Low                      DangerZone
```

## Security model

Two parties that talk over this layer authenticate each other, and everything they then exchange is
protected against tampering. **Nothing is encrypted.** That is a requirement, not a gap, and the rest
of this section says exactly what it does and does not buy you.

### What the handshake gives you

Each party owns an ECDSA P-256 identity key. The "0 Protocol" handshake has both sides sign a
transcript covering their identity, a nonce and a timestamp, and each verifies the other against the
key it already trusts for that remote — pinned in the remote's `.public` file, acquired by
configuration or by `AutoTrustKey` on first contact.

A signature that verifies against a key the sender supplied in the same message proves only that the
sender holds *some* private key. That is a trust-on-first-use decision, not a proof of identity, and
the code keeps the two apart (`SignatureCheck.SelfAsserted` versus `SignatureCheck.Trusted`). An
operator confirming such a key should compare its fingerprint out of band —
`IPublicKeyData.GetFingerprint()` exists for that.

Replays are refused: a nonce is single use per remote, and a message whose timestamp falls outside
`IRemoteKeys.MaxClockOffset` is rejected before anything else happens.

### What protects the frames afterwards

Authenticating the peer at connection time and stopping there would leave every subsequent frame
unprotected. The handshake therefore also carries an ephemeral ECDH exchange; both sides derive two
directional session keys from it and authenticate **every** run-phase frame with a 128-bit MAC
covering the header and the payload, over a counter that never repeats within a session.

So, after the handshake, an attacker on the path cannot inject a frame, alter one, reorder or replay
one, or retarget it at another protocol — any of those fail the MAC and the connection is dropped.

This also binds the session to the AppIdentity handshake itself, which matters for relays: a relay
holding two individually valid connections cannot derive the session key, so every frame it forwards
fails its MAC.

### What is deliberately NOT protected: confidentiality

Over `tcp:`, **message payloads travel in clear and anyone who can see the traffic can read them.**

This is deliberate. Being able to read every packet crossing the network is an operational
requirement for deployments that audit their own traffic, and auditing needs only that packets be
readable. Encrypting payloads by default would remove that, so this layer does not.

What this means when you build on it:

- Do not put a secret in a payload sent over `tcp:` and expect the transport to keep it. Passwords,
  tokens, personal data, business secrets — if it must not be read by whoever can see the wire, the
  application has to encrypt it before handing it over, or it must not travel over `tcp:`.
- Integrity is not confidentiality. "The frame is authentic" says an attacker cannot *change* it. It
  says nothing about who can *read* it.
- Traffic analysis is available to an observer regardless: who talks to whom, when, how often, and
  how large each message is. Frame lengths are in clear even for the handshake.
- An observer can read the identity keys exchanged in the handshake. They are public keys; this
  costs nothing beyond telling the observer which parties are talking.

A transport that does encrypt — mutual TLS, selected per remote by address — is the intended answer
for deployments that need confidentiality, and it coexists with `tcp:` rather than replacing it. The
two requirements are genuinely opposed, so the choice belongs to whoever configures the remote.
