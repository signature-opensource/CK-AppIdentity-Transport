# CK-AppIdentity-Transport

Communication between the parties modeled by [CK-AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/tree/stable):
parties find each other, authenticate each other with pinned keys, and exchange messages over a pluggable transport.

| Project | Description |
|---------|-------------|
| [CK.AppIdentity.KeyManagement](CK.AppIdentity.KeyManagement/README.md) | The identity keys of the parties: key event logs, pinned remotes, operational credentials and application signatures. |
| [CK.AppIdentity.KeyManagement.Cng](CK.AppIdentity.KeyManagement.Cng/README.md) | A key store that keeps the identity keys in a Windows CNG provider (TPM, HSM, smart card). |
| [CK.AppIdentity.TransportLayer](CK.AppIdentity.TransportLayer/README.md) | The transport: listeners, connections, the authenticating "0 Protocol" handshake, per-frame integrity and the channels. |
| [CK.AppIdentity.Transport.MutualTls](CK.AppIdentity.Transport.MutualTls/README.md) | The `mtls:` transport: the same handshake inside a mutually authenticated TLS channel. |
| [CK.AppIdentity.BlobChannel](CK.AppIdentity.BlobChannel/README.md) | A minimal channel that carries opaque `byte[]` between two parties. |
| [CK.AppIdentity.Cris](CK.AppIdentity.Cris/README.md) | A channel that carries Cris commands and their results between parties. |
| [CK.AppIdentity.Cris.AuthCenter](CK.AppIdentity.Cris.AuthCenter/README.md) | The "AuthCenter" feature core: the designation of the Authentication Center and the reading of its tokens. |
| [CK.AppIdentity.Cris.AuthCenter.Local](CK.AppIdentity.Cris.AuthCenter.Local/README.md) | This application is the Authentication Center: settings, sessions, token signing, login handlers. |
| [CK.AppIdentity.Cris.AuthCenter.Remote](CK.AppIdentity.Cris.AuthCenter.Remote/README.md) | This application is a front: it relays the session commands to its remote Authentication Center. |
| [CK.AppIdentity.Cris.AuthCenter.Oidc](CK.AppIdentity.Cris.AuthCenter.Oidc/README.md) | The OpenID Connect logins of a local Authentication Center. |
| [CK.AppIdentity.Cris.AuthCenter.Passkey](CK.AppIdentity.Cris.AuthCenter.Passkey/README.md) | The passkey (WebAuthn) logins of a local Authentication Center. |
| [CK.IO.AuthCenter](CK.IO.AuthCenter/README.md) | The relay protocol between the fronts and their Authentication Center. |
| [CK.DB.AppIdentity](CK.DB.AppIdentity/README.md) | The PartyActor: a CK-DB actor that represents a party. |
| [CK.Testing.AppIdentity.TransportLayer](CK.Testing.AppIdentity.TransportLayer/README.md) | Test helpers for the transport layer, including an adversarial peer. |
| [CK.Testing.AppIdentity.Cris](CK.Testing.AppIdentity.Cris/README.md) | Test helpers that run two applications talking over a Cris channel. |
