# CK-AppIdentity

The goal of this library is to provide a minimal model of an application and its peers
and to support extensibility thanks to simple "features" that can be associated to the
identity objects.

Application identity may be the only aspect that requires an explicit configuration.
Any other aspects can have a default behavior, but the remote parties with whom an application
interact and how they interact can hardly exist without configuration

The initial objects are defined by a standard [.Net configuration](https://learn.microsoft.com/en-us/dotnet/core/extensions/configuration)
that is locked and cannot be changed during the application lifetime. Configured objects are immutable
but one can dynamically define new objects and destroy dynamically defined objects.


## CK.AppIdentity
Contains the core objects:
- AppIdentityService is the root type. It is a singleton service that carries the 
  application identity and the remote parties.
- The [ApplicationIdentityFeatureDriver](CK.AppIdentity/ApplicationIdentityFeatureDriver.cs) is the base class
  to implement in order to manage features on the Application identity object objects.

## CK.AppIdentity.Configuration
This small library implements initialization of the identity configuration. 


## CK.AppIdentity.TransportLayer
Carries messages between parties. Parties authenticate each other with their identity keys and every
frame that follows is authenticated, but **payloads are not encrypted**: readable packets on the wire
are a requirement for deployments that audit their own traffic. See
[the security model](CK.AppIdentity.TransportLayer/README.md#security-model) before putting anything
confidential in a message.
