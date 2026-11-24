Test helpers for the CK-AppIdentity transport layer: `CreateApplicationServiceAsync` starts an
`ApplicationIdentityService` for a test, and the `AdversarialPeer` attacks real parties.

The service uses the "tcp" transport, with a `SystemClockTester`, fake data protectors, a
`PeeringIssueCollector` and a fault-injecting "bug" transport. The `AdversarialPeer` is an independent implementation of
the wire format that drives real parties with messages the production code would never produce.
