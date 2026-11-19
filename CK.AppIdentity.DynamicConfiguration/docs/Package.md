The dynamic configuration of a CK-AppIdentity application: `AppIdentityDynamicConfigurationStore` keeps the changes of the
run properties (CK.Cris.DynamicConfiguration) in the `-Local` store of the root party ("DynamicConfiguration.json"), so
that a change made by an `IConfigurePropertyCommand` survives a restart.
