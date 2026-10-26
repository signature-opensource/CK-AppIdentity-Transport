A CK-AppIdentity channel that carries Cris commands between parties: `CrisChannelFeature.SendCommand` sends a command to
a remote and returns its executing command (immediate events and result). The commands a remote sends are executed in the
`AppIdentityDIContainerDefinition` endpoint, where the calling `IRemoteParty` is a scoped service.
