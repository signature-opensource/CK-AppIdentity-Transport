The identity keys of CK-AppIdentity parties: each local party proves its identity with a key event log (pre-rotation,
recovery key), each remote is pinned by its last verified event. `KeyManagementFeatureDriver` adds an `ILocalKeys` to the
local parties and an `IRemoteKeys` to their remotes; `ILocalKeys.Sign` and `IPartyKeys.Verify` handle application
signatures (`ApplicationSignature`). Private keys are held by an `ICoreKeyStore` (`DefaultCoreKeyStore` by default).
