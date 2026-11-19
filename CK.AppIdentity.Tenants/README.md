# CK.AppIdentity.Tenants

The run-time tenant domains of a CK-AppIdentity System, managed by an operator. A run-time tenant domain is an instance of
an Opened tenant template of an application (see the run-time tenant domains in
[CK.AppIdentity](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/README.md)): this
package lets an operator create, move and remove them from a page of the System (the tenants page of CK-Ng-Admin), on
any application that holds templates. The commands are in
[CK.IO.AppIdentity.Tenants](../CK.IO.AppIdentity.Tenants/ITenantCommands.cs).

## Finding and reaching the applications

The Authentication Center is the hub of the System's administration (see `IPartyRelay` in CK.AppIdentity.Cris): every
party is linked to it.

- **The discovery** (`IGetTenantHostsQCommand`, on the application of the operator's page): the local application when
  it holds templates, its remotes that accept the tenant commands, and the remotes of its hub that accept them (the hub
  answers an `IGetAcceptingRemotesQCommand`: the commands advertised by the channels of its remotes). Nothing is announced
  nor stored. An application of the list may have no template (it only has this package): the page asks each one and keeps
  the ones that have some.
- **The reach:** the tenant commands are party commands (`ICommandTargetParty`: their `TargetPartyFullName` is the
  application). Sent to an application that is not a remote, they go through the hub.

So the application of the page (the Admin) needs no link with the applications that hold the tenants: both are linked to
the Authentication Center. This package is referenced by both: by the holders for the handlers of the tenant commands,
by the application of the page for the discovery.

## The commands

[`TenantHandlers`](TenantHandlers.cs) handles them by calling `IApplicationIdentityService` on the target application:

| Command | |
|---|---|
| `IGetTenantInstancesQCommand` | The Opened tenant templates (named by their domain prefix), their configured, run-time and unloaded instances (with their reason). |
| `ICreateTenantInstanceCommand` | `AddTenantInstanceAsync`: a new tenant of a template, named by the operator; its index is the first free one. |
| `ISetTenantIndexCommand` | `SetTenantIndexAsync`: a run-time tenant (loaded or not) moves to a free index; its identity doesn't change. |
| `IRemoveTenantInstanceCommand` | `RemoveTenantInstanceAsync`: its keys are destroyed, its private store trashed. |

They are Critical (`ICommandAuthCritical`): the user's proof travels with the command, through the hub. No right is
checked but the Critical level, unless the application adds a validator; a change made while impersonating is refused.
