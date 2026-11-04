The Local side of the CK-AppIdentity "AuthCenter" feature: a local party that allows "AuthCenter" is its own Authentication
Center. `LocalAuthCenter` holds the settings (`AuthCenterOptions`), the sessions and the signing of the tokens;
`AuthCenterOperationHandlers` handles the session operations, wherever their endpoint is. Its remotes are caller parties up
to Normal (`AuthCenterCallerPartyService`) or prove their users (`AuthCenterProofVerifier`). Scheme families plug in with
`IAuthCenterScheme`.
