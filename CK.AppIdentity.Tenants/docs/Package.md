The run-time tenant domains of a CK-AppIdentity System, managed by an operator. An application that holds Opened tenant
templates hosts the "Tenants" route (`TenantsFeatureDriver`); `TenantHandlers` handle the commands of
CK.IO.AppIdentity.Tenants by calling `IApplicationIdentityService` (`AddTenantInstanceAsync`, `SetTenantIndexAsync`,
`RemoveTenantInstanceAsync`). A tenant command whose target is not a remote travels along the "Tenants" route
(`TenantCommandRouteProvider`). No right is checked but the Critical level, unless the application adds a validator.
