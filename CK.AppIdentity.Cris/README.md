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

Only the caller-only events cross the channel: they travel with the response. The caller-only immediate events appear
in `IExecutingCommand.ImmediateEvents`, the caller-only final events in the `Events` of the executed command. The routed
events stay in the remote party: they are dispatched where the command executed.

A command is executed by the remote only if the remote accepts it from us (see below).

## Accepted commands

A party never executes whatever a remote sends: `CrisChannelFeature.IsAcceptedFromRemote` decides, from the deployment
topology, what this party accepts from the remote of the channel:

| Command | Accepted from the remote |
|---|---|
| Not handled here, or not a command | never |
| `[Private]` | never |
| `[Internal]` | only when the remote is inside the System (`IsRemoteInsideSystem`: it shares the `DomainName` and the `EnvironmentName` of its owner) |
| Public | always |

Endpoint-only commands are accepted when they are handled: they are sent explicitly with `SendCommand`. On each
connection, each side advertises the names of the commands it accepts from the other: `AcceptedCommands` is what the
remote accepts from us (null until its first advertisement, see `WaitForAcceptedCommandsAsync`).

## Location-transparent dispatch

[`ChannelCrisRemoteDispatcher`](ChannelCrisRemoteDispatcher.cs) implements the `ICrisRemoteDispatcher` of CK.Cris.Executor:
the code that executes a command doesn't care whether it runs here or on a remote.

- **A command without local handler** (a singleton command: one eventual handler for the local party, a local handler
  always wins) is sent to the remote of the current local party that accepts it. No remote is "no route"; more than one
  is a deployment error (also logged when the advertisements show it).
- **A party command** (`ICommandTargetParty`) is routed by its `TargetPartyFullName` before any local execution: the
  current local party executes it here; another local party of the application (the root or a tenant) executes it here,
  inline, as its `CurrentLocalParty` (an independent execution: its routed events are dispatched in that party's scope);
  a remote of the current local party receives it if it accepts it; anything else is "no route".

While a remote has not advertised yet, a command without route waits for it, up to `ChannelCrisRemoteDispatcher.Timeout`
(30 seconds), which also bounds the wait for an answer. It fails closed: no route, an unavailable remote or no answer
is an error result, never a local execution. The caller-only events of the remote execution are emitted in the caller's
execution context.

## Executing the remote's commands

A received command that is not accepted from the remote, or a party command whose target is not the owner of the
remote, is refused before any validation (an error result, logged with the `SecurityCritical` tag). Otherwise, it is
always validated as an incoming command, then executed by the `CrisExecutionHost` in the
[`AppIdentityDIContainerDefinition`](AppIdentityDIContainerDefinition.cs) endpoint. In this endpoint:

- the calling `IRemoteParty` is a scoped service;
- the `CurrentLocalParty` is the owner of that remote (the root application or the tenant domain that knows it);
- the ambient services have their default values (except the ones the command's incoming validation configures, such
  as its culture): nothing in the message can claim a user identity.

The caller-only events and the final result are sent back on the high priority queue of the transport, the final
events before the result. A command that cannot be read is answered with an error result.

## The protocol

A message starts with a discriminator byte, read by [`CrisChannelFeature.Protocol`](CrisChannelFeature.Protocol.cs):

| Discriminator | Direction | Content |
|---------------|-----------|---------|
| 1 | Caller to callee | The issuer token of the command, then the command (typed JSON). |
| 2 | Callee to caller | The key of the issuer token, then an immediate event (typed JSON). |
| 3 | Callee to caller | The key of the issuer token, then the `ICrisCallResult` (JSON). |
| 4 | Callee to caller | The key of the issuer token, then a final caller-only event (typed JSON), before the result. |
| 5 | Both ways, on each connection | The names of the commands the sender accepts from the receiver. |

The JSON uses the "AllExchangeable" type filter.
