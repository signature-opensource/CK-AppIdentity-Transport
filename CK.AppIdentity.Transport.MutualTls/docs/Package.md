The "mtls" transport of CK-AppIdentity: the "0 Protocol" handshake inside a mutually authenticated TLS channel, for
remotes whose payloads must not be readable on the wire.

`MutualTlsTransportTypeService` implements it (default port 37121). The certificates are derived from each party's
identity key and bound to it inside the signed handshake: nothing to configure.
