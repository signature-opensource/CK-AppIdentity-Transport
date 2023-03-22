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

