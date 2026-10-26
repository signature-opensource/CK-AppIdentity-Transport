The Local side of the CK-AppIdentity "AuthCenter" feature: this application is the Authentication Center of its local
parties. `LocalAuthCenter` holds the settings (`AuthCenterOptions`), the sessions and the signing of the tokens; it handles
the session and login commands and the commands relayed by its fronts. Scheme families plug in with `IAuthCenterScheme`.
