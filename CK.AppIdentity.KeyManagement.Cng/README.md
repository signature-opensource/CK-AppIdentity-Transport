# CK.AppIdentity.KeyManagement.Cng

The default key store of [CK.AppIdentity.KeyManagement](../CK.AppIdentity.KeyManagement/README.md) keeps the identity
keys in files: a copied, backed-up or stolen host gives them away. This package keeps them in a Windows CNG key storage
provider instead: the TPM by default, or any provider an HSM or a smart card vendor ships. Keys are created inside the
provider, are not exportable, and every signature is made by it.

What it does not prevent: code running on the host while it is compromised can use the keys (but never take them away).
That is what an offline recovery key is for (`RecoveryPublicKey` and `ILocalKeys.Recover`, see
[CK.AppIdentity.KeyManagement](../CK.AppIdentity.KeyManagement/README.md#configuration)).

## Registration

[`CngCoreKeyStore`](CngCoreKeyStore.cs) is an `ICoreKeyStore` whose constructor is
`( DefaultCoreKeyStore fallback, IServiceProvider? services )`: taking the default store is how the automatic DI makes it
replace the default store, and how it falls back to it. Referencing the package is enough.

The settings of a party come from the KeyManagement feature driver (`KeyManagementFeatureDriver.GetOption<CngKeyStoreOption>( party )`,
resolved on first use from the `services`). Without the services, the store only opens, lists and deletes the existing keys.

## Configuration

The store is the "CngKeyStore" option of the KeyManagement feature: [`CngKeyStoreOption`](CngKeyStoreOption.cs), in the
`"KeyManagement"` section of a local party (see
[the options of the party components](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/PartyComponentOptions/README.md#the-configuration)).
It is enabled by default: referencing this package says that the keys must be in the provider.
`"KeyManagement": { "CngKeyStore": false }` puts the keys of a party in files (the `DefaultCoreKeyStore`).

```jsonc
"KeyManagement": {
  "CngKeyStore": {
    "Provider": "Microsoft Platform Crypto Provider", // The default: the TPM.
    "AllowFallback": false,                           // The default.
    "MachineWide": false                              // The default.
  }
}
```

The option is resolved as a whole: the `"CngKeyStore"` of the party's `"KeyManagement"`, otherwise the one of the
`"KeyManagement"` of the nearest `"Defaults"` above it (the whole section, not value by value). So an option in the
`"Defaults"` of the root applies to the application and to every tenant domain, which may replace it in its own
`"KeyManagement"` or `"Defaults"` (see
[the structural levels and the defaults](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Configuration/README.md#the-structural-levels-and-the-defaults)).

| Key | Default | |
|-----|---------|---|
| `Provider` | `Microsoft Platform Crypto Provider` (`CngCoreKeyStore.DefaultProviderName`, the TPM) | The CNG provider name. |
| `AllowFallback` | `false` | When `true` and the provider is not usable (another OS, no chip, a chip disabled in firmware, a missing driver), keys go to the `DefaultCoreKeyStore` with a warning. When `false`, an unusable provider stops the party from starting rather than silently downgrading to file keys. Set it in the `"Defaults"` of the root for a mixed fleet. |
| `MachineWide` | `false` | When `true`, keys are CNG machine keys (default access: administrators and LocalSystem) instead of keys of the service account, for services whose account may change. Creating them in the TPM provider usually needs administrative rights. |

An invalid option (an unknown key, an empty `Provider`, a value of `AllowFallback` or `MachineWide` that is neither
`true` nor `false`) is an error: the setup fails.

`IsUsable( providerName, out reason )` tells whether a provider can create keys on this machine, for this account. A
provider is probed once (with an ephemeral key) and the answer is cached.

## Where each key is

CNG cannot enumerate keys without native calls, so each key has a marker file next to where the default store keeps its
files (`CoreKeys/{name}.cng` in the local party's `LocalFileStore`): its provider, its scope (`user` or `machine`) and its
CNG name, one per line. The CNG name is `CK.AppIdentity.{scope}.{name}`, where the scope is derived from the store folder,
so that two stores on one machine never share a key of the same party.

Opening and destroying a key use its marker, never the current configuration: changing the provider orphans nothing, new
keys go to the new provider and the next rotation moves the identity across. Keys of the default store (created before
this store was used, under `AllowFallback`, or with the option disabled) stay readable, except when keys are required in a provider that is not
usable: the party must then not run on file keys at all.
