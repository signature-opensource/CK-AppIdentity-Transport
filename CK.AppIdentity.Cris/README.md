# CK.AppIdentity.Cris

A channel of [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md) that carries
[Cris](https://github.com/signature-opensource/CK-Cris/blob/stable/README.md) commands between parties: a party sends a
command to a remote, the remote executes it and sends back its immediate events and its result.

This channel carries no user identity: the only identity that is established is the one of the remote party itself,
authenticated by the transport. Authentication over this channel is the subject of a package built on it,
[CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md).

## Activation

[`CrisChannelFeatureDriver`](CrisChannelFeatureDriver.cs) manages the "CrisChannel" feature, allowed by default: every
remote that has a `TransportFeature` gets a [`CrisChannelFeature`](CrisChannelFeature.cs). Its protocol is "Cris", in
version 0.

The driver requires a `CrisExecutionHost`
([CK.Cris.BackgroundExecutor](https://github.com/signature-opensource/CK-Cris/blob/stable/CK.Cris.BackgroundExecutor/README.md))
to execute the received commands, and the `PocoDirectory`: commands, events and results travel as JSON.

## Sending a command

```csharp
var cris = remote.GetRequiredFeature<CrisChannelFeature>();
var executing = cris.SendCommand( monitor, command );
var executed = await executing.ExecutedCommand;
```

`SendCommand` never throws for a remote failure: the `ExecutedCommand` eventually carries the remote result, or an
`ICrisResultError` when the command cannot be sent or its result cannot be read. A command is queued and sent as soon as
a connection to the remote exists; once connected, what is queued survives a reconnection. When the remote is
destroyed, the commands still waiting complete with an error.

The immediate events the remote execution emits appear in `IExecutingCommand.ImmediateEvents`. The other events stay in
the remote party: the `Events` of the executed command are always empty.

## Executing the remote's commands

A received command is always validated as an incoming command, then executed by the `CrisExecutionHost` in the
[`AppIdentityDIContainerDefinition`](AppIdentityDIContainerDefinition.cs) endpoint. In this endpoint:

- the calling `IRemoteParty` is a scoped service;
- the `CurrentLocalParty` is the owner of that remote (the root application or the tenant domain that knows it);
- the ambient services have their default values: nothing in the message can claim a user identity.

The immediate events and the final result are sent back on the high priority queue of the transport. A command that
cannot be read is answered with an error result.

## The protocol

A message starts with a discriminator byte, read by [`CrisChannelFeature.Protocol`](CrisChannelFeature.Protocol.cs):

| Discriminator | Direction | Content |
|---------------|-----------|---------|
| 1 | Caller to callee | The issuer token of the command, then the command (typed JSON). |
| 2 | Callee to caller | The key of the issuer token, then an immediate event (typed JSON). |
| 3 | Callee to caller | The key of the issuer token, then the `ICrisCallResult` (JSON). |

The JSON uses the "AllExchangeable" type filter.
