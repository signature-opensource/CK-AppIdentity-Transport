The Remote side of the CK-AppIdentity "AuthCenter" feature: a local party relays its authentication to the remote that is
its Authentication Center.
Its endpoints execute the session commands and the AuthCenter their operations (dispatched to it). `RemoteAuthCenter`
verifies the users' proofs relayed by other parties by asking the AuthCenter, `AuthCenterFieldEncryptor` encrypts the sensitive fields for it,
`RemoteAuthCenter` holds its current encryption key.
