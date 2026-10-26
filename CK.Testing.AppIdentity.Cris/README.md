# CK.Testing.AppIdentity.Cris

Test helpers that run two real applications talking over the Cris channel of
[CK.AppIdentity.Cris](../CK.AppIdentity.Cris/README.md): a "Test/$Sender" that connects to a "Test/$Listener".

## Running the applications

`CreateCrisSenderApplicationAsync` and `CreateCrisListenerApplicationAsync` (extensions of `IMonitorTestHelper`, in the
`CK.Testing` namespace) create a started [`RunningApplication`](RunningApplication.cs):

- the CK engine runs for the application in its own output folder (`$StObjGen/Sender/{n}` or `$StObjGen/Listener/{n}`),
  with the transport, the key management, the Cris channel and the test commands below, plus the given types;
- the sender connects to the listener on `tcp:127.0.0.1:37140` (`RunningApplication.Port`), and both pin each other on
  first contact (`AutoTrustKey` is `Once`, and each application has a fresh key store);
- the clock has no heartbeat (`SystemClockTester.NoHeartBeat`) and the data protection is the `FakeProtector`
  (see [CK.Testing.AppIdentity.TransportLayer](../CK.Testing.AppIdentity.TransportLayer/README.md)).

The `configuration` callback runs after this configuration and `configureServices` after these services: both can change
anything. A `RunningApplication` exposes its `ApplicationIdentityService`, its `TransportManagerFeature` (`Transport`),
the `CrisChannel` to the other application, its `PocoDirectory` and `Services`; disposing it disposes everything.

## Test commands

| Type | |
|------|---|
| `ISenderCommand` | Sent by the sender. The `ListenerHandler` emits an `IListenerImmediateEvent` and answers "Listener received '...'". |
| `IListenerCommand` | Sent by the listener. The `SenderHandler` answers "Sender received '...'". |
| `IWhoAmICommand` | Answered by the listener with "{calling party full name}/{actor name}", as seen by the listener. |
