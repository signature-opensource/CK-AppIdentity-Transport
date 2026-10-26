`CngCoreKeyStore`: an `ICoreKeyStore` that keeps the identity keys of CK-AppIdentity parties in a Windows CNG
provider (the TPM by default, or an HSM or a smart card provider), non exportable. It replaces the `DefaultCoreKeyStore`
and is configured by the "CoreKeyStore:CngProvider", "CoreKeyStore:AllowFallback" and "CoreKeyStore:MachineWide" keys.
