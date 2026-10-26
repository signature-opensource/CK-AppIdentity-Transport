# CK.AppIdentity.Cris.AuthCenter.Passkey

The passkey (WebAuthn) logins of the Authentication Center ([CK.AppIdentity.Cris.AuthCenter.Local](../CK.AppIdentity.Cris.AuthCenter.Local/README.md): only an AuthCenter application references it; a front only needs the commands):
the "Passkey" scheme. The Authentication Center alone runs the protocol and verifies, with
[Fido2NetLib](https://github.com/passwordless-lib/fido2-net-lib): the browser's response is signed by the user's
authenticator over a challenge chosen here, so a front can relay it but cannot forge nor replay it. The passkeys are kept by
an `IPasskeyStore` ([CK.AuthenticationInfo.Passkey](https://github.com/signature-opensource/CK-Auth-Abstractions/blob/stable/CK.AuthenticationInfo.Passkey/README.md)),
implemented by a storage package; the commands are in CK.IO.Authentication.Passkey.

An application that doesn't use passkeys doesn't reference this package (nor Fido2NetLib and its NSec/libsodium dependency).

## Configuration

```jsonc
"AuthCenter": {
  "Passkey": {
    "RpId": "example.com",                          // The relying party: a passkey is bound to it (never change it).
    "RpName": "Example",                            // Optional: defaults to the RpId.
    "Origins": [ "https://app.example.com" ],       // The origins of the endpoints: the RpId or its sub-domains, https.
    "Timeout": "00:05:00"                           // Optional: the lifetime of a ceremony (at most 10 minutes).
  }
}
```

[`AuthCenterPasskeyConfiguration`](AuthCenterPasskeyConfiguration.cs) declares the "Passkey" section.
[`AuthCenterPasskeyFeatureDriver`](AuthCenterPasskeyFeatureDriver.cs) adds an [`AuthCenterPasskey`](AuthCenterPasskey.cs)
family to every local Authentication Center (tenants included). The "Passkey" scheme is available (listed, accepted) when
the section exists **and** an `IPasskeyStore` is registered; otherwise the family has no scheme and hides the "Passkey"
provider name.

## The rules ([`AuthCenterPasskeyHandlers`](AuthCenterPasskeyHandlers.cs))

- **Origins:** a ceremony is accepted only from an endpoint whose `WebOrigin` is a configured origin (a front relays its
  checked origin), and the origin signed by the browser must be this one: a phishing page signs its own origin and is
  refused. The relying party hash must be the `RpId`'s.
- **User verification required** (PIN, biometrics), at registration and at login: `userVerification: "required"` is
  asked, and the UV flag is checked. A passkey login gives the Critical level, like any login.
- **Usernameless login:** `IStartPasskeyLoginCommand` has no parameter and the options list no credential: starting a
  login reveals nothing about the accounts. The response must carry the user handle of the passkey's owner.
- **Ceremonies:** in memory, one use, under their challenge, for the `Timeout`, at most 10,000 (starting a login is
  anonymous). A login response cannot complete a registration, nor a ceremony started from another origin.
- **Signature counter:** a non-zero counter that does not increase is refused (a cloned authenticator). Synchronized
  passkeys always send 0: accepted.
- **Registration:** `ICommandAuthCritical`, refused below the Critical level or while impersonating (a passkey added by
  a stolen session or by an impersonator would be a lasting access to the account), and completed by **the session that
  started it**. Discoverable credentials (`residentKey: "required"`), ES256 and RS256, attestation `none` (the AAGUID is
  declared, not attested: display only). A credential identifier that is already stored (for any actor) is refused.
- **The responses** are limited to 16 KB when they enter the System (the incoming validators are in
  CK.IO.Authentication.Passkey: a front that relays them refuses them too). Nothing in them is secret (a signature over a one use
  challenge, a public key).

On success, the session is opened with a `PasskeyLoginPayload` (the verified credential identifier, counter and backup
state) for the "Passkey" `ILoginProvider` of the storage package, that records the counter and the last use.
