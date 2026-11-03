The Local side of the CK-AppIdentity "AuthCenter" feature: this application is the Authentication Center of its local
parties. `LocalAuthCenter` holds the settings (`AuthCenterOptions`), the sessions and the signing of the tokens;
`AuthCenterOperationHandlers` handles the session operations, wherever their endpoint is. Its remotes are caller parties up
to Normal (`AuthCenterCallerPartyService`) or prove their users (`AuthCenterProofVerifier`). Scheme families plug in with
`IAuthCenterScheme`.
