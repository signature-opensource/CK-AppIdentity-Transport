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


## Message Prefix: Message Protocol and Length

The prefix starts with a first byte: `|L0|L1|P0|P1|P2|P3|P4|P5|`. The 2 first bytes (L0-L1) gives us the number of
bytes of the message length:
- `00` 1 byte, the message length is between 0 and 255 bytes.
- `01` 2 bytes, the message length is between 256 and 65535 bytes.
- `10` 3 bytes, the message length is between 65536 and 16 777 215 bytes.
- `11` 4 bytes, the message length is between 16 777 216 and 2 147 483 640 bytes (2 Gib minus 8 bytes is the maximal message length).
Then comes the message length itself (1 to 4 bytes), then the message payload itself.

P0-P5 bits encodes the Protocol Number that is a number between 0 and 64. This protocol number defines the "type" of the
message: the reader or "deserializer" that has been used to write the payload and must be used to read it back.

The protocol "0" is reserved: this is the protocol of CK.AppIdentity.TransportLayer itself. This protocol
handles special messages used to negotiate, accept, reject incoming parties and outgoing connections.
This lets 63 "real" message protocols available.

The wire-length of a message is between 2 bytes (the special Empty message, see below) and 2 Gib.
A 1 byte message requires 3 bytes (in any of the 63 available protocols). 

Three special TransportMessage exists. The first 2 messages never cross a frontier, they can
only be used locally on a party:
- The `TransportMessage.Invalid` is a message invalid singleton, used when an invalid message is received.
- The `TransportMessage.Canceled` is a second message invalid singleton, that can be used when a read operation is canceled.
- The `TransportMessage.Empty` is a valid singleton that can be exchanged: it is used
for KeepAlive messages. Its length on the wire is 2 bytes and is the shortest message that exists. Regular protocols
(other than the "0" one) are not allowed to send empty messages.



