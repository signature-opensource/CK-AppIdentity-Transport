The Remote side of the CK-AppIdentity "AuthCenter" feature: this application is a front of a remote Authentication
Center. `AuthCenterRelay` relays the session commands and the commands executed by the Authentication Center, with their
sensitive fields encrypted for it; `RemoteAuthCenter` holds its current encryption key.
