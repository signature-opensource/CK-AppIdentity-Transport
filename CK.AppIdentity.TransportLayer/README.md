# Transport Layer

## Configuration keys

`IRemoteParty.Address` is the only modeled property: it can only be defined on a RemoteParty and is optional.
When not specified, then the Remote is Client: we must act as a Server, meaning that we must listen to
incoming connections until the Remote establishes the connection. When listening to incoming connections, a
single local end point can handle connections from more than one RemoteParty: the `ListeningAddress` is a
configuration property that can be defined once, at the root level (ApplicationIdentityService), but nothing
prevents this `ListeningAddress` to be defined at any configuration level: the closest wins. This enables
a dedicated listening address for a Domain or even for a specific Remote.

An `Address` or a `ListeningAddress` are mere strings: their exact syntax depends on the type of Transport that
must be used. This type can be specified with the standard URI protocol syntax: 'tcp:', 'quic:', 'pipe:', etc. and when
not specified, it defaults to 'tcp:'.

When a `IRemoteParty.Address` is not specified, a third and last property can be used to disambiguate the type of
transport listener to use: the `UseTransport` property is a string that must be the transport protocol name of
a one of the `ListeningAddress` defined above.

A `ListeningAddress` property at one level can be a string, a comma separated string or an array of strings,
but when more than one address is specified, there must be only one address per type of Transport. This is valid
`"ListeningAddress": [ "tcp:localhost:37120", "pipe:TheNamedPipe" ]`.

## TransportMessage
A [`TransportMessage`](TransportMessage.cs) is a `ReadOnlySequence<byte>` with a prefixed length and a Protocol number.
The message is `IDisposable`: it holds its memory buffers that are pooled array of bytes. Messages can only be created
by 3 methods of the [`TransportMessageFactory`](TransportMessageFactory.cs).


## Message Prefix: Protocol and Length

All messages exchanged by the Transport layer are prefixed by the message's protocol and length.
- The prefix starts with a first byte: `|L0|L1|R0|R1|R2|P0|P1|P2|`.
  - The 2 MSB (L0-L1) gives us the number of bytes of the message length:
    - `00` 1 byte, the message length is between 0 and 255 bytes.
    - `01` 2 bytes, the message length is between 256 and 65535 bytes.
    - `10` 3 bytes, the message length is between 65536 and 16 777 215 bytes.
    - `11` 4 bytes, the message length is between 16 777 216 and 2 147 483 648 bytes (2 Gib).
  - The `R0`, `R1` and `R2` bits are reserved for future use.
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

Three special singletons TransportMessage exist (all tied to the "0 Protocol").
The first 2 messages never cross a frontier, they can only be used locally on a party:
- The `TransportMessage.Invalid` is the "invalid" message, used when an invalid message is received.
- The `TransportMessage.Canceled` is a second "invalid" message, that is used to signal a canceled read operation.
- The `TransportMessage.Empty` is a valid message that can be exchanged: it is used
for KeepAlive messages. Its length on the wire is 2 bytes and is the shortest message that exists. Regular protocols
(other than the "0 Protocol") are not allowed to send empty messages.



