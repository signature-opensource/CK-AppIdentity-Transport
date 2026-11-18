using CK.Auth;
using CK.Core;
using CK.Cris;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Tenants;

/// <summary>
/// Lists the applications that hold tenant templates: the hosts of the "Tenants" route of the local party that executes it
/// (the host of the operator's page). A singleton command, executed where it is sent.
/// </summary>
public interface IGetTenantHostsQCommand : ICommand<IList<string>>, ICommandAuthCritical
{
}

/// <summary>
/// Lists the Opened tenant templates of an application (<see cref="ICommandTargetParty.TargetPartyFullName"/>) and their
/// instances: the configured ones, the run-time ones and the unloaded ones (with their reason).
/// </summary>
public interface IGetTenantInstancesQCommand : ICommand<IList<ITenantTemplateInfo>>, ICommandTargetParty, ICommandAuthCritical
{
}

/// <summary>
/// An Opened tenant template of an application.
/// </summary>
public interface ITenantTemplateInfo : IPoco
{
    /// <summary>
    /// Gets or sets the name of the template: its domain prefix ("Sample/Auth3/Customers").
    /// </summary>
    string TemplateName { get; set; }

    /// <summary>
    /// Gets or sets the number of configured instances.
    /// </summary>
    int ConfiguredCount { get; set; }

    /// <summary>
    /// Gets or sets the maximal number of instances (the configured ones included).
    /// </summary>
    int MaxInstanceCount { get; set; }

    /// <summary>
    /// Gets the instances: the configured ones, the run-time ones (loaded or not).
    /// </summary>
    IList<ITenantInstanceInfo> Instances { get; }
}

/// <summary>
/// An instance of an Opened tenant template.
/// </summary>
public interface ITenantInstanceInfo : IPoco
{
    /// <summary>
    /// Gets or sets the name of the instance ("Acme").
    /// </summary>
    string Name { get; set; }

    /// <summary>
    /// Gets or sets the full name of its tenant domain.
    /// </summary>
    string FullName { get; set; }

    /// <summary>
    /// Gets or sets its index, null when its record can't be read.
    /// </summary>
    int? Index { get; set; }

    /// <summary>
    /// Gets or sets whether it is a configured instance (it is changed by the configuration, not by these commands).
    /// </summary>
    bool IsConfigured { get; set; }

    /// <summary>
    /// Gets or sets why it is not loaded (<c>UnloadedTenantReason</c>: "IndexTaken", "IndexAboveBound"...), null when it is
    /// loaded.
    /// </summary>
    string? UnloadedReason { get; set; }

    /// <summary>
    /// Gets or sets the explanation of <see cref="UnloadedReason"/>.
    /// </summary>
    string? UnloadedMessage { get; set; }
}

/// <summary>
/// Creates a run-time tenant domain in an application (<see cref="ICommandTargetParty.TargetPartyFullName"/>): an
/// instance of its template <see cref="TemplateName"/> named <see cref="Name"/>, with the first free index. Its result is
/// the full name of the new tenant domain, null on error.
/// </summary>
public interface ICreateTenantInstanceCommand : ICommand<string?>, ICommandTargetParty, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the name of the template: its domain prefix.
    /// </summary>
    string TemplateName { get; set; }

    /// <summary>
    /// Gets or sets the name of the new instance ("Acme").
    /// </summary>
    string Name { get; set; }
}

/// <summary>
/// Moves a run-time tenant domain (loaded or not) of an application to another free index: its identity doesn't change.
/// </summary>
public interface ISetTenantIndexCommand : ICommand<bool>, ICommandTargetParty, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the tenant domain.
    /// </summary>
    string TenantFullName { get; set; }

    /// <summary>
    /// Gets or sets the new index.
    /// </summary>
    int Index { get; set; }
}

/// <summary>
/// Removes a run-time tenant domain (loaded or not) of an application: its identity is deleted (its keys), its private
/// store trashed. A new tenant of the same name is a new identity.
/// </summary>
public interface IRemoveTenantInstanceCommand : ICommand<bool>, ICommandTargetParty, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the tenant domain.
    /// </summary>
    string TenantFullName { get; set; }
}
