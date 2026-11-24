The run-time tenant domains of a CK-AppIdentity System, managed by an operator: the handlers of the tenant commands of
CK.IO.AppIdentity.Tenants.

`TenantHandlers` handle them by calling `IApplicationIdentityService` (`AddTenantInstanceAsync`, `SetTenantIndexAsync`,
`RemoveTenantInstanceAsync`), and find the applications that hold tenant templates through the hub of the System (its
Authentication Center). A tenant command whose target is not a remote goes through the hub. No right is checked but the
Critical level, unless the application adds a validator.
