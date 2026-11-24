# CK.AppIdentity.AuthCenter.Password

The password login of the CK Authentication Center ([CK.AppIdentity.AuthCenter.Local](../CK.AppIdentity.AuthCenter.Local/README.md): only an AuthCenter
application references it): the "Password" option of the AuthCenter (`AuthCenterPasswordOption`, `TypeActivation.ByDefault`), whose
scheme family (`AuthCenterPassword`) makes the "Basic" (a user name and a password) scheme available.

- **The family only.** The scheme is available when the option is enabled for the party **and** its login provider is
  registered: the provider is the backend's (`UserPasswordLoginProvider` of CK.DB.User.UserPassword for a SQL Server database, or any other). The option doesn't bring it: a backend may not be a
  database.
- **No account creation:** an unknown identity is refused (the accounts are created by the administration).
- **Turned off** by `"AuthCenter": { "Password": false }` in the party (or its `"Defaults"`): the scheme is neither listed by
  `IGetLoginSchemesQCommand` nor accepted (`"Authentication.UnknownScheme"`).
