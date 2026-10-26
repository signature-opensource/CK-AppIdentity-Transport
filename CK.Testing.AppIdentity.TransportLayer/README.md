# CK.Testing.AppIdentity.TransportLayer

Test helpers for [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md), shared by the test
projects so that a second, divergent copy of the harness does not appear. Its centerpiece is an adversarial peer: an
independent implementation of the wire format, used to drive real parties with messages the production code would never
produce.

## Running a party

`TestHelperExtensions.CreateApplicationServiceAsync` (an extension of `IMonitorTestHelper`, in the `CK.AppIdentity`
namespace) builds a service provider, starts the `ApplicationIdentityService` from a configuration and waits for its
initialization. It registers the `MessageProtocolDirectoryService`, the transport and key management drivers, the
`DefaultCoreKeyStore` with the `FakeProtector` as `IDataProtectionProvider`, and the `tcp:` transport only. Its
`configureServices` runs last: it adds another transport (`mtls:` or the buggy one below) or replaces what is registered,
the system clock in particular.

The store root is not set here: each test assembly sets it from its own folder in a `[SetUpFixture]`, otherwise two
assemblies would share one store.

| Type | |
|------|---|
| [`SystemClockTester`](SystemClockTester.cs) | A clock with an adjustable `Offset`. `SystemClockTester.NoHeartBeat` has no heartbeat at all. |
| [`FakeProtector`](FakeProtector.cs) | An `IDataProtector` (and provider) that does not protect anything. |
| [`HeaderProtector`](HeaderProtector.cs) | An `IDataProtector` that transforms the data and refuses what it did not protect, to catch a Protect/Unprotect mismatch the fake one cannot see. |
| [`PeeringIssueCollector`](PeeringIssueCollector.cs) | Records `PeeringIssue` snapshots as they change and waits for a given `PeeringIssueKind`. |
| [`BasicAsyncReader`](BasicAsyncReader.cs) | Turns an outgoing message into a stream an `IncomingMessageFactory` can read back. |
| [`BugTransportTypeService`](BugTransport/BugTransportTypeService.cs) | The "bug" transport type: its address is a combination of `BugType` flags that make the parsing, the listener, the connection, the reads, the writes or the disposals fail. |

## The adversarial peer

The types of the `CK.AppIdentity.TransportLayer.Testing.Adversarial` namespace speak the Zero Protocol without the
production code: a harness built on the production writer could only produce what that writer is willing to produce.

| Type | |
|------|---|
| [`AdversarialPeer`](Adversarial/AdversarialPeer.cs) | A hostile listener a real initiator connects to (`Address`, `AcceptAsync`), or a hostile initiator (`ConnectAsync`). With a `PeerCertificate`, it speaks `mtls:`. |
| [`PeerConnection`](Adversarial/AdversarialPeer.cs) | One connection: reads frames and the InitialMessage, sends "0 Protocol" frames or raw bytes. |
| [`PeerWire`](Adversarial/PeerWire.cs) | An independent codec of the wire header. |
| [`PeerMessages`](Adversarial/PeerMessages.cs) | Builders of the negotiation messages, signed with whatever the test chooses. |
| [`PeerInitialMessage`](Adversarial/PeerInitialMessage.cs) | A parsed InitialMessage. |
| [`PeerIdentity`](Adversarial/PeerIdentity.cs) | A key event log of the peer's own (`Create`, `Rotate`, `Recover`, `Abandon`), or someone else's log with stolen keys (`Adopt`). |
| [`PeerCredential`](Adversarial/PeerCredential.cs) | An operational credential, including ones production never issues (wrong usage, CA, expired, overlong). |
| [`PeerCertificate`](Adversarial/PeerCertificate.cs) | A TLS certificate minted independently, with its truthful `Binding`. |
| [`PeerStore`](Adversarial/PeerStore.cs) | Store surgery: clears or reads what a party pins for a remote, or clears a local party, so that a test starts from a known state. |
