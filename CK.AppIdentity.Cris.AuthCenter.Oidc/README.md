# CK.AppIdentity.Cris.AuthCenter.Oidc

The OpenID Connect logins of the Authentication Center ([CK.AppIdentity.Cris.AuthCenter](../CK.AppIdentity.Cris.AuthCenter/README.md)):
the "Oidc.&lt;Suffix&gt;" schemes, with the authorization code flow and PKCE. The local Authentication Center alone holds the
client secrets: a front relays the start of a login and the callback, like any session command.

An application that doesn't use OpenID Connect doesn't reference this package (nor Microsoft.IdentityModel).

## Configuration

```jsonc
"AuthCenter": {
  "Oidc": {
    "Google": {                                   // The scheme is "Oidc.Google".
      "Authority": "https://accounts.google.com", // https (http only on a loopback address).
      "Issuer": "...",                            // Optional: defaults to the Authority.
      "ClientId": "...",
      "ClientSecret": "...",
      "TokenEndpointAuthMethod": "...",           // Optional: "client_secret_basic" or "client_secret_post" (see below).
      "Scopes": "openid email",                   // "openid" is always included.
      "CallbackUrls": [ "https://app.example.com/.auth/oidc/callback" ]
    }
  }
}
```

[`AuthCenterOidcConfiguration`](AuthCenterOidcConfiguration.cs) declares the "Oidc" section: without this package, the
section is a configuration error of the Authentication Center.

## The family

[`AuthCenterOidcFeatureDriver`](AuthCenterOidcFeatureDriver.cs) adds an [`AuthCenterOidc`](AuthCenterOidc.cs) to every
local Authentication Center (the root and the tenants, dynamic ones included), with the schemes of its section (possibly
none: the family still hides the "Oidc" provider name in the scheme listing). `AuthCenterOidc` is the
`IAuthCenterRemoteScheme` of these schemes: the core of the Authentication Center handles the remote login commands and the
pending logins, this package runs the protocol.

1. **Start:** the callback of the endpoint must be one of the scheme's `CallbackUrls`. The nonce and the PKCE verifier are
   generated here and kept with the pending login; the result is the authorization URL.
2. **Completion:** the code is redeemed (client secret + PKCE verifier) at the token endpoint (see the client
   authentication below) and the identity token is validated: signature (the provider's keys, read again once on an unknown
   key), issuer, audience, lifetime, then the protocol rules of `OpenIdConnectProtocolValidator` (nonce, `at_hash`, required
   claims). The messages are `OpenIdConnectMessage`: the protocol is the one of Microsoft.IdentityModel (the library of the
   ASP.NET handler, that cannot be used here: it is bound to an HTTP request, the Authentication Center receives Cris
   commands).
3. The login uses the **"Oidc" login provider**: its payload must have the writable string properties `SchemeSuffix` and
   `Sub` (the payload of CK.DB.User.UserOidc for instance). The session is opened like any login.

**The client authentication at the token endpoint** is `client_secret_basic` by default, the default of the
specification: an HTTP Basic `Authorization` header, whose client id and secret are form-url-encoded before being joined
(RFC 6749 section 2.3.1: a `:` in the id or the secret stays unambiguous). Without `TokenEndpointAuthMethod`, the
`token_endpoint_auth_methods_supported` of the discovery document decides: `client_secret_basic` when it is absent or
announces it, `client_secret_post` (the secret in the body) only when it announces it and not the basic one. A provider
that announces neither (only `private_key_jwt`, `tls_client_auth`...) is refused at the start of the login: the user is
not sent to it. One method per request, the secret is never sent twice.

**One issuer per scheme:** `sub` is unique per issuer only and the identity of an actor is (scheme, sub). The issuer
announced by the provider and the `iss` of the tokens must be exactly the configured one: multi-tenant endpoints (whose
issuer varies) are not supported.

**No automatic account creation or binding:** a login succeeds only for an actor already bound to the identity. The
family allows no account creation (yet: a per-scheme `AllowAccountCreation` setting is designed).
