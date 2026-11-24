# CK.AppIdentity.AuthCenter.Weak

The weak logins of the CK Authentication Center ([CK.AppIdentity.AuthCenter.Local](../CK.AppIdentity.AuthCenter.Local/README.md): only an AuthCenter
application references it): the "Weak" option of the AuthCenter (`AuthCenterWeakOption`, `TypeActivation.ByDefault`), whose
scheme family (`AuthCenterWeak`) makes the "Weak" (a weak actor, at most at the Unsafe level) scheme available.

- **The family only.** The scheme is available when the option is enabled for the party **and** its login provider is
  registered: the provider is the backend's (`WeakActorTable` of CK.DB.Actor.WeakActor for a SQL Server database, or any other). The option doesn't bring it: a backend may not be a
  database.
- **No account creation:** an unknown identity is refused (the accounts are created by the administration).
- **Turned off** by `"AuthCenter": { "Weak": false }` in the party (or its `"Defaults"`): the scheme is neither listed by
  `IGetLoginSchemesQCommand` nor accepted (`"Authentication.UnknownScheme"`).
