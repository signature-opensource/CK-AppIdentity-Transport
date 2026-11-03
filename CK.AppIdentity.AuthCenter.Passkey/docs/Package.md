The passkey (WebAuthn) logins of the CK Authentication Center: the "Passkey" scheme, configured in the
"AuthCenter:Passkey" section of the Authentication Center's "Local" and verified by the Authentication Center alone with Fido2NetLib (usernameless login, user
verification required, registration at the Critical level in the starting session, attestation "none"). The passkeys
are kept by an `IPasskeyStore` (CK.AuthenticationInfo.Passkey). Reference it only when passkeys are wanted.
