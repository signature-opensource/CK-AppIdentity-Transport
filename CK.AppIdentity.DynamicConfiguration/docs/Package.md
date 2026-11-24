The dynamic configuration of a CK-AppIdentity application: the changes of its run properties
(CK.Cris.DynamicConfiguration) are kept in the store of its root party.

`AppIdentityDynamicConfigurationStore` keeps them in the `-Local` store of the root party ("DynamicConfiguration.json"),
so that a change made by an `IConfigurePropertyCommand` survives a restart.
