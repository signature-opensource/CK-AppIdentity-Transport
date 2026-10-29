# CK.Testing.AppIdentity.Cris.AuthCenter

Test helpers for an application that is its own Authentication Center
([CK.AppIdentity.Cris.AuthCenter.Local](../CK.AppIdentity.Cris.AuthCenter.Local/README.md)) and its HTTP front
(CK.Cris.AspNet.Authentication): a single process and a single party, the shape of many real deployments (a front
application directly on its backend party). The tests of the packages built on the authentication (the Angular
packages, for instance) run their server with it.

## The engine configuration

`AddAuthCenterApplication()` (an extension of `BinPathConfiguration`, in the `CK.Testing` namespace) adds the
`AuthCenterApplicationAssemblies` to the BinPath: `CK.AppIdentity.Cris.AuthCenter.Local` and
`CK.Cris.AspNet.Authentication` (the engine finds the rest through their references).

The test adds what is specific to it:

- the login schemes (`CK.Cris.Authentication.Basic`...) and their providers (`CK.DB.User.UserPassword`...), or fakes;
- a **TypeScript configuration aspect**: the HTTP front reads only the commands of the "TypeScript" type set. A test
  without TypeScript tooling uses `TestHelper.GetTypeScriptGeneratedOnlyTargetProjectPath()` (only the `ck-gen` folder
  is generated).

## The running application

`CreateRunningAuthCenterApplicationAsync( map, identity, configureApplication )` (an extension of
`WebApplicationBuilder`) creates and starts the application:

- its identity: `DefaultIdentity` ("Test/$AuthCenter", whose root is its own Authentication Center:
  `"Local": { "AllowFeatures": "AuthCenter" }`, with the default settings) unless the `identity` callback configures another one;
- the data protection is the `FakeProtector`
  (see [CK.Testing.AppIdentity.TransportLayer](../CK.Testing.AppIdentity.TransportLayer/README.md)): the identity keys
  are not really protected at rest;
- `AddCrisAuthentication()`, then the `configureApplication` callback, `UseCrisAuthentication()` and `UseCris()`.

The returned `RunningAspNetServer` (CK.Testing.AspNetServer) is ready: its identity service is initialized. Its `Client`
keeps the cookies, so a session opened on `/.cris/auth` works with the token of the `ISessionResult`: a client sets the
`ActorId` of the commands' authentication parts, like the TypeScript client does with the ambient values.

For an example, see the
[SingleApplicationTests](../Tests/CK.AppIdentity.Cris.AuthCenter.Tests/SingleApplicationTests.cs).
