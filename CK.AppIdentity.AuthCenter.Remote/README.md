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

## Without a channel to the Authentication Center ([`AnchoredAuthCenter`](AnchoredAuthCenter.cs))

A local party that has no remote allowing `"AuthCenterRemote"` can designate its Authentication Center by its full name,
`"Local:AuthCenterParty"`. The Authentication Center must then have a trust anchor (`"Local:TrustAnchors"`, see
[CK.AppIdentity.KeyManagement](../CK.AppIdentity.KeyManagement/README.md)), otherwise the setup fails. With a remote that
allows `"AuthCenterRemote"`, `"AuthCenterParty"` must name it (the channel is used).

```jsonc
"CK-AppIdentity": {
  "FullName": "Acme/$Worker",
  "Local": {
    "AuthCenterParty": "Acme/$Center/#Prod",
    "TrustAnchors": { "Acme/$Center/#Prod": "12:8e2a980dea..." }
  },
  "Parties": [ { "PartyName": "Front" } ] // No channel to the Center: its route goes through the Front.
}
```

The local party gets a `CrisAuthCenter` whose `AuthCenter` is null and an `AnchoredAuthCenter` (the
`IAuthCenterProofChecker` and the `IPartyEncryptionKeyDirectory`). Everything it needs from the Authentication Center
travels along its `"AuthCenter"` route, verified with its keys, whatever the hops (the driver then needs the
`AnchoredKeyDirectory` and the `PartyRoutedCommandSender` of CK.AppIdentity.Cris, resolved from the root services):

- **The keys:** its key events, fetched by the key directory of CK.AppIdentity.Cris (`AnchoredKeyDirectory`) and
  verified from the anchor: the tokens are read here.
- **A user's proof received directly** is read here (the token and its binding): its session is not asked. A logout or a
  revocation takes effect at the end of the critical window (the liveness lag accepted without a channel).
- **A user's proof received with a routed command** is verified by the Authentication Center
  (`IVerifyRoutedProofQCommand`): only it has the keys of the session party that sealed the command. It also checks the
  session at once. Its answer is a statement it signs (`AuthCenterProofStatement`: the destination, a nonce chosen by
  this party, the digests of the token and of the seal).
- **The encryption keys** of the Authentication Center and of its remotes are its statements
  (`IGetRemoteEncryptionKeyQCommand`).

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
package). The `RemoteAuthCenter` reads the current encryption key of the Authentication Center in its description
(`PartyDescription.EncryptionKey`), verifies its signature (`PartyEncryption.KeyPurpose`, with the same safety net as
the tokens) and caches it until it changes or its signature expires.
