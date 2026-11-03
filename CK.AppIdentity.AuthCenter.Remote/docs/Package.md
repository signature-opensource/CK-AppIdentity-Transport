The Remote side of the CK-AppIdentity "AuthCenter" feature: this application is a remote of an Authentication Center.
Its endpoints execute the session commands and the AuthCenter their operations (dispatched to it). `AuthCenterProofContributor`
sends the user's proof to the AuthCenter only, `AuthCenterFieldEncryptor` encrypts the sensitive fields for it,
`RemoteAuthCenter` holds its current encryption key and resolves the PartyActor identifiers.
