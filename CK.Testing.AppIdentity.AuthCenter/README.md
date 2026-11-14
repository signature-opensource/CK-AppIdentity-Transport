# CK.Testing.AppIdentity.AuthCenter

Test helpers for an application that is its own Authentication Center
([CK.AppIdentity.AuthCenter.Local](../CK.AppIdentity.AuthCenter.Local/README.md)) and its HTTP front
(CK.Cris.AspNet.Authentication): a single process and a single party, the shape of many real deployments (a front
application directly on its backend party). The tests of the packages built on the authentication (the Angular
packages, for instance) run their server with it.

## The engine configuration

`AddAuthCenterApplication()` (an extension of `BinPathConfiguration`, in the `CK.Testing` namespace) adds the
`AuthCenterApplicationAssemblies` to the BinPath: `CK.AppIdentity.AuthCenter.Local`, `CK.Cris.AspNet.Authentication`
and `CK.AppIdentity.HttpEndpoint` (the engine finds the rest through their references).

The test adds what is specific to it:

- the login schemes (`CK.Cris.Authentication.Basic`..., or the Angular packages that bring them) and their providers:
  the database packages (`CK.DB.User.UserPassword`...), or the fakes of
  [CK.Testing.Cris.Authentication](https://github.com/signature-opensource/CK-Cris/blob/stable/CK.Testing.Cris.Authentication/README.md)
  (`AddFakeLoginProviders()`: the actors of its `FakeActorDatabase`, "Albert" 3712 with the password "success"...);
- a **TypeScript configuration aspect**: the HTTP front reads only the commands of the "TypeScript" type set. A test
  without TypeScript tooling uses `TestHelper.GetTypeScriptGeneratedOnlyTargetProjectPath()` (only the `ck-gen` folder
  is generated).

## The running application

`CreateRunningAuthCenterApplicationAsync( identity, configureHost, configureEndpoint )` (an extension of `IStObjMap`)
creates and starts the application, a party: the `IStObjMap.CreateRunningAspNetServerAsync` of
[CK.Testing.AspNetServer](https://github.com/signature-opensource/CK-AspNet/blob/stable/CK.Testing.AspNetServer/README.md)
(a Generic Host whose web application is the endpoint of its "HttpEndpoint" feature, on a random port):

- its identity: `DefaultIdentity` ("Test/$AuthCenter", whose root is its own Authentication Center:
  `"Local": { "AllowFeatures": "AuthCenter" }`, with the default settings) unless the `identity` callback configures another one;
- the data protection is the `FakeProtector`
  (see [CK.Testing.AppIdentity.TransportLayer](../CK.Testing.AppIdentity.TransportLayer/README.md)): the identity keys
  are not really protected at rest;
- the Cris authentication and Cris middlewares are the contributions of their packages to the endpoint
  (`EnableCrisAuthentication`, `EnableCris`): the test calls nothing.

The returned `RunningAspNetServer` (CK.Testing.AspNetServer) is ready: its identity service is initialized. Its `Client`
keeps the cookies, so a session opened on `/.cris/auth` works with the token of the `ISessionResult`: a client sets the
`ActorId` of the commands' authentication parts, like the TypeScript client does with the ambient values.

For an example, see the
[SingleApplicationTests](../Tests/CK.AppIdentity.AuthCenter.Tests/SingleApplicationTests.cs).
