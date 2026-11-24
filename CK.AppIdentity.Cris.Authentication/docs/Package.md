The identity of the users across the CK-AppIdentity Cris channels: a received command executes with the identity of its
user, vouched for by the calling party or proved by the user's token.

The calling party vouches with `AuthenticationInfo.CallerPartyFullName`, capped by the receiver's `ICallerPartyService`
and never Critical; the user's token is an `IAuthenticationCallEnvelope`, checked by an `ICallerProofVerifier`. Main
type: `AuthenticationReceptionHandler`.
