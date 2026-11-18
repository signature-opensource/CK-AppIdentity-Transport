# CK.AppIdentity.Tenants

The run-time tenant domains of a CK-AppIdentity System, managed by an operator. A run-time tenant domain is an instance of
an Opened tenant template of an application (see the run-time tenant domains in
[CK.AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/README.md)): this
package lets an operator create, move and remove them from a page of the System (the tenants page of CK-Ng-Admin), on
any application that holds templates. The commands are in
[CK.IO.AppIdentity.Tenants](../CK.IO.AppIdentity.Tenants/ITenantCommands.cs).

## The "Tenants" route

An application that holds Opened tenant templates hosts the "Tenants" route on its root party
([`TenantsFeatureDriver`](TenantsFeatureDriver.cs), a "Tenants" feature allowed by default). The route is:

- **the discovery:** the host of the operator's page lists the hosts of its "Tenants" routes (`IGetTenantHostsQCommand`:
  no list is stored, the routes are announced by the parties);
- **the reach:** the tenant commands are party commands (`ICommandTargetParty`: their `TargetPartyFullName` is the
  application). Sent to an application that is not a remote, they travel along the "Tenants" route
  ([`TenantCommandRouteProvider`](TenantCommandRouteProvider.cs), see the party commands beyond one hop of
  CK.AppIdentity.Cris).

A route is accepted only toward an authorized host: the "RouteHosts" of the Authentication Center of the System (or of
the local party) must authorize the hosts of "Tenants".

## The commands

[`TenantHandlers`](TenantHandlers.cs) handles them by calling `IApplicationIdentityService` on the target application:

| Command | |
|---|---|
| `IGetTenantInstancesQCommand` | The Opened tenant templates (named by their domain prefix), their configured, run-time and unloaded instances (with their reason). |
| `ICreateTenantInstanceCommand` | `AddTenantInstanceAsync`: a new tenant of a template, named by the operator; its index is the first free one. |
| `ISetTenantIndexCommand` | `SetTenantIndexAsync`: a run-time tenant (loaded or not) moves to a free index; its identity doesn't change. |
| `IRemoveTenantInstanceCommand` | `RemoveTenantInstanceAsync`: its keys are destroyed, its private store trashed. |

They are Critical (`ICommandAuthCritical`): the user's proof travels with the command along the route. No right is
checked but the Critical level, unless the application adds a validator; a change made while impersonating is refused.
