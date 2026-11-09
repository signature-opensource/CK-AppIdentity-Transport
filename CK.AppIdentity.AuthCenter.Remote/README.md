# CK.AppIdentity.AuthCenter.Remote

The Remote side of the [AuthCenter feature](../CK.AppIdentity.AuthCenter/README.md): **a local party relays its
authentication to a remote Authentication Center**. Its [`RemoteAuthCenterFeatureDriver`](RemoteAuthCenterFeatureDriver.cs)
adds a [`RemoteAuthCenter`](RemoteAuthCenter.cs) to every local party that doesn't allow `"AuthCenter"` (in its
`"Local"`) and has a remote that allows `"AuthCenterRemote"`: this remote is its Authentication Center (more than one is
a configuration error, a remote added later can be it). A local party that allows `"AuthCenter"` is ignored:
CK.AppIdentity.AuthCenter.Local handles it, and the two packages can be referenced by the same application.

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Front",
  "Parties": [
    { "PartyName": "Center", "AllowFeatures": "AuthCenterRemote" }, // The Authentication Center.
    { "PartyName": "Box" }
  ]
}
```

The Authentication Center must announce it (the roles of its description): a `"Center"` whose `"Local"` doesn't allow
`"AuthCenter"` is an error when it announces its description.

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

## The user's proof

The proof is sent to any party of the System, read here with the Authentication Center's keys, and its liveness is
asked to the Authentication Center (`RemoteAuthCenter.CheckLivenessAsync`): see [CK.AppIdentity.AuthCenter](../CK.AppIdentity.AuthCenter/README.md#the-users-proof).

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
