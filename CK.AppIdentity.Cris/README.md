# CK.AppIdentity.Cris

A channel of [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md) that carries
[Cris](https://github.com/signature-opensource/CK-Cris/blob/stable/README.md) commands between parties: a party sends a
command to a remote, the remote executes it and sends back its immediate events and its result.

This channel carries no user identity: the only identity that is established is the one of the remote party itself,
authenticated by the transport. Authentication over this channel is the subject of a package built on it,
[CK.AppIdentity.AuthCenter](../CK.AppIdentity.AuthCenter/README.md).

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
destroyed, the commands still waiting complete with an error. With a `timeout`, a command that is not executed in time
completes with a "Cris.Timeout" error and is abandoned: not sent if it is still queued, its late answers ignored. Bound
the wait with this `timeout`, never with a `WaitAsync` on the `ExecutedCommand`: the command would stay pending.

Only the caller-only events cross the channel: they travel with the response. The caller-only immediate events appear
in `IExecutingCommand.ImmediateEvents`, the caller-only final events in the `Events` of the executed command. The routed
events stay in the remote party: they are dispatched where the command executed. The receiver enforces it: any other
event received from the remote (a local event would be dispatched to the local handlers, in the caller's identity) is
refused with a `SecurityCritical` warning, and its command completes with an error.

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
remote accepts from us (null until its first advertisement, see `WaitForAcceptedCommandsAsync`). An `[Internal]` command
never leaves the System: the ones advertised by a remote outside the System are ignored (a `SecurityCritical` warning),
so that such a remote can neither receive nor block their dispatch.

The advertisement also carries the description of the party (`IParty.Description` of
[CK.AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/README.md#the-description-of-a-party):
its public URL, its client applications, its roles, its data announcements, its routes, the items collected along them
and its encryption key): the receiver sets it on its remote (`IRemoteParty.SetDescription`, persisted but for the
routes, the collected items and the key). It is sent again when the local description changes (`ILocalParty.DescriptionChanged`: the HTTP endpoints know
their URL once the host has started). An invalid description is logged and ignored: the remote keeps its last known one.

Its binary form is [`PartyDescriptionCodec`](PartyDescriptionCodec.cs): the description and each client application are
length-prefixed blocks (see the blocks of [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/Buffering/README.md)),
so that a field added at the end of a block is skipped by the readers that don't know it.

## Location-transparent dispatch

[`ChannelCrisRemoteDispatcher`](ChannelCrisRemoteDispatcher.cs) implements the `ICrisRemoteDispatcher` of CK.Cris.Executor:
the code that executes a command doesn't care whether it runs here or on a remote.

- **A command without local handler** (a singleton command: one eventual handler for the local party, a local handler
  always wins) is sent to the remote of the current local party that accepts it. No remote is "no route"; more than one
  is a deployment error (also logged when the advertisements show it).
- **An endpoint-only command** (`ICommandEndpointOnly`, like a login command) is never dispatched: it executes on the
  endpoint that receives it (that may send something else to a remote, like the session operation of a login). Several
  remotes that accept it are not a deployment error.
- **A party command** (`ICommandTargetParty`) is routed by its `TargetPartyFullName` before any local execution: the
  current local party executes it here; another local party of the application (the root or a tenant) executes it here,
  inline, as its `CurrentLocalParty` (an independent execution: its routed events are dispatched in that party's scope);
  a remote of the current local party receives it if it accepts it; anything else is "no route".

While a remote has not advertised yet, a command without route waits for it, up to `ChannelCrisRemoteDispatcher.Timeout`
(30 seconds), which also bounds the wait for an answer (the command is then abandoned). It fails closed: no route, an unavailable remote or no answer
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

## Routed commands ([`IPartyRoutedCommand`](IPartyRoutedCommand.cs))

A command for a party of the System that is not a remote travels in an `IPartyRoutedCommand`, sent by the
[`PartyRoutedCommandSender`](PartyRoutedCommandSender.cs) of the originating local party:

- **The command travels as bytes** (`IPartyRoutedCommand.SealedCommand`): the JSON of the command with its type,
  serialized once by the originating party with the exchange options of the channels. The hops never read it; the
  destination executes the command read from these exact bytes. An optional
  [`ICrisRoutedCommandSeal`](ICrisRoutedCommandSeal.cs) seals them at the origin (once the envelope contributors filled
  the envelope) and unseals them at the destination (before the command is read): the authentication packages sign the
  bytes with the user's proof for the destination. The seal may also seal the result: the destination sends back an
  `IPartySealedResult` (the result, sealed), the origin unseals it; the events of such a
  command are not relayed back. An error made on the way (by a hop, before the execution) is not sealed; any other
  result that the origin expects sealed and receives in clear is refused.
- **The destination** is a named party reached along a route (`SendAsync( ..., routeName, destination )`: each hop takes
  its next hop from its own `PartyDescription.Routes`, see `PartyRoute`), or the last party of an explicit path
  (`SendAlongPathAsync`: for an answer, the way back to the party a request came from). A name can have several hosts:
  the origin and each hop take the route of the name that leads to `IPartyRoutedCommand.Destination`, and refuse the
  command (fail closed) when there is none; the seal is made for the destination, never for the host of a route. See
  [Route hijacking](docs/RouteHijacking.md): a route is announced, not proven.
- **Each hop** is a party command (`ICommandTargetParty`): its target is the next hop, so the usual reception checks
  apply (it is `[Internal]`: inside the System only). The channel handles it, never a command handler: it checks the
  chain (the last of `Via` is the remote that sent it, no loop, at most `PartyRoute.MaxLength` parties), adds the local
  party to `Via` and forwards it with its envelope, on its own task (no runner is held). The envelope is relayed as
  received, once the `ICrisForwardedEnvelopeFilter` cleared what this party can't vouch for (the authentication packages
  remove a user's proof that the hop can't verify). The answers come back by the chain of calls.
- **The answer** is the result only (`Task<object?>`): the validation messages of the destination don't come back (an
  error result carries its errors).
- **Time:** the `PartyRoutedCommandSender` waits at most its `timeout` (by default `ChannelCrisRemoteDispatcher.Timeout`)
  for the first hop and the answer (the seal's lookups have their own timeouts): never wrap it in a `WaitAsync`, it would go on with the caller's monitor and services.
  Each party gives the next one less time than it has (`IPartyRoutedCommand.TimeBudget`, half a second less): a hop
  forwards only when time is left, at most the `ChannelCrisRemoteDispatcher.Timeout`, so that its error (an unavailable
  next hop, no answer) reaches the origin before the origin gives up.
- **The destination** unseals the bytes (on its own task), reads the command (refused when they are not a command) and executes it like a
  received one (incoming validation, then execution), as long as it handles it, it is not `[Private]`, not endpoint-only (its `IRemoteParty` would be the last hop), and not another routed
  command. The caller party is the originating one ([`CrisCallerParty`](CrisCallerParty.cs), the first of `Via`): an
  `ICrisChannelReceptionHandler` must configure its ambient services (the identity), or the command is refused. Without
  reception handler (no authentication package), it executes with the clean ambient services: no identity, the local party
  as the current one. Routing needs nothing else than this package. `Via` holds the full names of the parties: the full
  name is the identity of a party across the System.

The destination believes the chain: each hop authenticated its predecessor, inside the System. A chain that contains
a revoked party (its name banned by the revocations of the Authentication Center, see CK.AppIdentity.KeyManagement) is
refused by any party (a `SecurityCritical` warning): a hop that still relays for it lies, or is not up to date. The outgoing transformers
(`ICrisOutgoingCommandTransformer`) are not applied: a routed command's sensitive fields can't be encrypted for its
destination.

## The keys of an anchored party ([`AnchoredKeyDirectory`](AnchoredKeyDirectory.cs))

A party that anchors another one (see the trust anchors of CK.AppIdentity.KeyManagement) without a channel to it gets
its keys along a route that the anchored party hosts: `CheckAsync` checks a signature of the anchored party and, when its
issuer is unknown (nothing is held yet, or the party rotated since), sends an
[`IGetKeyEventsQCommand`](IGetKeyEventsQCommand.cs) along the route, from the point it holds (`FromSeq`: its anchor,
then the head it holds), applies the events (`IAnchoredKeys.ApplyEvents`) and checks the signature again, once.
`RefreshAsync` fetches without a signature to check.

- **Checked, never believed:** the events are verified from the anchor (the full name is in the digest of each event): a
  hop can withhold them, not forge them. The route must lead to the anchored party (its host is its full name).
- **On demand:** a fetch waits at most `FetchTimeout` (2 seconds) for the answer (when a seal applies to the query,
  depending on the envelope of the caller's services, it is sealed first: the seal's lookups have their own timeouts);
  concurrent fetches of the same party share one request, and a party is fetched at most once every `MinFetchInterval`
  (5 seconds), so signatures with an unknown issuer can't make a party flood the route.
- **The answer** ([`KeyEventsHandler`](AnchoredKeyDirectory.cs)): the destination sends its own events from `FromSeq`, up to
  the window of 32 events (its last events when `FromSeq` is out of the window). Key events are public: any party of the
  System can ask: it needs no identity (with or without a reception handler).

## The protocol

A message starts with a discriminator byte, read by [`CrisChannelFeature.Protocol`](CrisChannelFeature.Protocol.cs):

| Discriminator | Direction | Content |
|---------------|-----------|---------|
| 1 | Caller to callee | The issuer token of the command, then the `ICrisCallEnvelope` that contains it (typed JSON). |
| 2 | Callee to caller | The key of the issuer token, then an immediate event (typed JSON). |
| 3 | Callee to caller | The key of the issuer token, then the `ICrisCallResult` (JSON). |
| 4 | Callee to caller | The key of the issuer token, then a final caller-only event (typed JSON), before the result. |
| 5 | Both ways, on each connection | The names of the commands the sender accepts from the receiver. |

The JSON uses the "AllExchangeable" type filter.
