# CK.AppIdentity.Cris.AuthCenter.Remote

The Remote side of the [AuthCenter feature](../CK.AppIdentity.Cris.AuthCenter/README.md): **this application is a remote**
of an Authentication Center. Its [`RemoteAuthCenterFeatureDriver`](RemoteAuthCenterFeatureDriver.cs) adds a
[`RemoteAuthCenter`](RemoteAuthCenter.cs) to every local party that allows the "AuthCenter" feature (in its `"Local"`, or
in a `"Defaults"` above it): its Authentication Center is **the** remote that allows the feature (more than one is a
configuration error). An application has one role: an Authentication Center references
CK.AppIdentity.Cris.AuthCenter.Local.

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Front",
  "Local": { "AllowFeatures": "AuthCenter" },
  "Parties": [
    { "PartyName": "Center", "AllowFeatures": "AuthCenter" },   // The Authentication Center.
    { "PartyName": "Box" }
  ]
}
```

## How a remote authenticates its users

A remote has no login provider and no session store. Its endpoints execute the session commands themselves, with the
endpoint packages of CK-Cris (CK.Cris.Authentication and its per-scheme packages): the session state stays with the
endpoint (its secrets never leave it). What needs the Authentication Center's state (opening a session, a refresh, a
logout, an impersonation, a remote login, the passkey ceremonies) is an `[Internal]` **operation command** that the
endpoint executes: a remote has no handler for it, so the location-transparent dispatch of
[CK.AppIdentity.Cris](../CK.AppIdentity.Cris/README.md) sends it to the Authentication Center over the Cris channel. It
fails closed: an unavailable or unreachable Authentication Center is an error, never a local execution.

The commands handled by the Authentication Center (any command, an operation or not) are dispatched the same way. They
carry the identity of their user (see [CK.AppIdentity.Cris.Authentication](../CK.AppIdentity.Cris.Authentication/README.md)):
this remote vouches for it, and in an interactive request it also sends the user's proof.

## The user's proof ([`AuthCenterProofContributor`](AuthCenterProofContributor.cs))

For a command that carries an identity, sent to the Authentication Center of the current local party, it puts the token
and the binding secret hash presented to this endpoint in the command's envelope (`IAuthenticationCallEnvelope`). A
proof is a bearer credential: it is never sent to another party. A deferred execution has no presented proof: the remote
alone vouches for the user, and the Authentication Center caps the level at Normal.

## The sensitive fields ([`AuthCenterFieldEncryptor`](AuthCenterFieldEncryptor.cs))

The [Sensitive] strings of a command sent to the Authentication Center (for instance the password of a Basic login, in
the payload of the operation that opens the session) are encrypted for it, in a copy of the command: the generated
`TransformSensitiveStrings` of the command finds them, nested Cris Pocos included. A command whose sensitive fields have
no value is sent as is.

## The tokens and the encryption key of the Authentication Center

The tokens are verified with the pinned keys of the Authentication Center (see the key events safety net in the core
package). The `RemoteAuthCenter` gets the current encryption key of the Authentication Center with
`IGetAuthCenterEncryptionKeyQCommand`, verifies its signature ("CK.AuthCenter.EncryptionKey" purpose, with the same
safety net as the tokens) and caches it until its signature expires.

## The PartyActor identifiers

A remote of an Authentication Center usually has no actors database. Once the features are set up, its
`RemoteAuthCenter` sends `IGetPartyActorIdsQCommand` on the Cris channel to the Authentication Center (sent as soon as
the channel connects) and sets the `PartyActorId` of its local party and of the Authentication Center with the answer.
`RemoteAuthCenter.PartyActorIdsResolution` completes with true once they are set, false when they cannot be (the
Authentication Center has not resolved them, or there is no Cris channel to it). Nothing is asked when both
identifiers are already set (the application has the CK.DB.AppIdentity registrar).
