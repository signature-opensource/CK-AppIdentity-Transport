`CngCoreKeyStore`: an `ICoreKeyStore` that keeps the identity keys of CK-AppIdentity parties in a Windows CNG
provider (the TPM by default, or an HSM or a smart card provider), non exportable.

It replaces the `DefaultCoreKeyStore`
and is the "CngKeyStore" option of the KeyManagement feature (`CngKeyStoreOption`, enabled by default):
"KeyManagement:CngKeyStore:Provider", "KeyManagement:CngKeyStore:AllowFallback" and "KeyManagement:CngKeyStore:MachineWide";
`"KeyManagement": { "CngKeyStore": false }` puts the keys of a party in files.
