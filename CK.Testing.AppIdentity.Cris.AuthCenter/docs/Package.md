Test helpers for an application that is its own Authentication Center and its HTTP front (one process, one party):
`AddAuthCenterApplication()` adds the assemblies of CK.AppIdentity.Cris.AuthCenter.Local and
CK.Cris.AspNet.Authentication to a BinPath, and `CreateRunningAuthCenterApplicationAsync` starts the application (its
identity, a fake data protection, the Cris authentication and Cris middlewares).

See the [README](https://github.com/signature-opensource/CK-AppIdentity-Transport/blob/stable/CK.Testing.AppIdentity.Cris.AuthCenter/README.md).
