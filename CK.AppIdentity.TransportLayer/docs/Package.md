The transport of CK-AppIdentity parties: listeners and connections, the "0 Protocol" handshake that authenticates both
sides against pinned keys, a MAC on every frame afterwards (payloads stay readable), and up to 7 channels per remote.
Entry points: `TransportFeature` (on each remote), `TransportManagerFeature` (peering issues), `ChannelFeatureDriver<T>`
and `ChannelFeature` (channels), `TransportTypeService` (transport types; "tcp" is built in).
