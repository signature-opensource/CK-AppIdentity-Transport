# CK.AppIdentity.Cris.Authentication

The identity of the users across the [CK.AppIdentity.Cris](../CK.AppIdentity.Cris/README.md) channels. A command that a
remote party sends executes, at the receiving party, with the identity of its user: the remote **vouches** for that
user (it is the *caller party*), or sends the user's **proof**.

## The rules ([`AuthenticationReceptionHandler`](AuthenticationReceptionHandler.cs))

This package implements the channel's `ICrisChannelReceptionHandler`. For a received command (never an endpoint-only
one, which keeps the channel scope):

- `AuthenticationInfo.CallerPartyId` is the `PartyActorId` of the calling remote (see
  [CK.AppIdentity.Abstractions](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity.Abstractions/README.md)).
- An anonymous command executes as the anonymous.
- A command that carries an identity (an `IAuthUnsafePart` whose actor is not the anonymous) is refused when the caller
  has no `PartyActorId` (0).
- With the user's proof and an [`ICallerProofVerifier`](ICallerProofVerifier.cs) that accepts it, the identity is the
  proved one, with its level.
- Otherwise, the actors are read from the command's identifiers (`CrisAuthenticationService.ReadActorsAsync`) and the
  level is the one the command requires, capped by the receiver's `ICallerPartyService` (without one, every caller party
  is refused) and never above `Normal`: **a caller party alone never reaches Critical**. A command whose level cannot be
  granted is refused (`Authentication.CallerPartyRefused`, logged with the `SecurityCritical` tag).

The identity is then validated by the incoming validators of the command's authentication parts, as for any received
command.

## The user's proof ([`IAuthenticationCallContext`](IAuthenticationCallContext.cs))

A Poco extension of the channel's `ICrisCallContext`: the token and the binding secret hash that the user presented to
the sending endpoint. A proof is a bearer credential: it must only be sent to a party that verifies it. The
Authentication Center packages ([CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md)) send it
to the AuthCenter only and verify it there. A deferred execution has no proof: the caller party vouches.
