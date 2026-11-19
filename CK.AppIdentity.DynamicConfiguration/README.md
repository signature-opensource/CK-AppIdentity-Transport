# CK.AppIdentity.DynamicConfiguration

The dynamic configuration (CK.Cris.DynamicConfiguration) of a CK-AppIdentity application: `AppIdentityDynamicConfigurationStore`
keeps the changes of its run properties in the `-Local` store of its root party (`DynamicConfiguration.json`, written
atomically; a local party runs in one process at a time, so the file has one writer). With it, a change made by an
`IConfigurePropertyCommand` survives a restart (unless the configured value changed since then: the latest decision
wins).

An application references it with CK.Cris.DynamicConfiguration (whose engine, CK.Cris.DynamicConfiguration.Engine, its
builder references). The commands (CK.IO.DynamicConfiguration) are party commands: an operator sends them to the root
party of the application, directly or through the hub of the System.
