The identity of the users across the CK-AppIdentity Cris channels: a received command executes with the identity of its
user, vouched for by the calling party (`AuthenticationInfo.CallerPartyId`, capped by the receiver's
`ICallerPartyService`, never Critical) or proved by the user's token (`IAuthenticationCallEnvelope`, checked by an
`ICallerProofVerifier`). Main type: `AuthenticationReceptionHandler`.
