The Local side of the CK-AppIdentity "AuthCenter" feature: a local party that declares "AuthCenter" is its own
Authentication Center, with its settings, its sessions, the signing of its tokens and the policy for its remotes.

`LocalAuthCenter` holds the settings (`AuthCenterOptions`), the sessions and the signing of the tokens;
`AuthCenterOperationHandlers` handles the session operations, wherever their endpoint is. Its remotes are caller parties up
to Normal (`AuthCenterCallerPartyService`) and `LocalAuthCenter` checks the users' proofs relayed by any party of the System (`VerifyCallerProofHandler`). Scheme families plug in as
options of the AuthCenter (`IAuthCenterSchemeFamilyOption`) that create an `IAuthCenterScheme`.
