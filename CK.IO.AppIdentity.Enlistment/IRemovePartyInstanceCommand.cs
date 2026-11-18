using CK.Core;
using CK.Cris;
using CK.Auth;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Enlistment;

/// <summary>
/// Lists the dynamic instances of the Opened remote templates that reach the approval page: the instances that have been
/// approved (their identity is pinned by their holder), collected along the "Enlistment" route by the host of the page.
/// Critical, like the approval: the list exposes the names of the parties.
/// </summary>
public interface IGetPartyInstancesQCommand : ICommand<IList<IPartyInstance>>, ICommandAuthCritical
{
}

/// <summary>
/// A dynamic instance (<see cref="PartyFullName"/>) of an Opened remote template of a holder.
/// </summary>
public interface IPartyInstance : IPoco
{
    /// <summary>
    /// Gets or sets the full name of the instance.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the full name of the party that holds the instance (the local party of the template).
    /// </summary>
    string HolderFullName { get; set; }

    /// <summary>
    /// Gets or sets the party name of the template, with its placeholders: "$Worker-{Name}".
    /// </summary>
    string TemplatePartyName { get; set; }
}

/// <summary>
/// Removes a dynamic instance of an Opened remote template: sent by the approval page. The host of the page sends it to
/// every party that holds the instance (see <see cref="IRemoveHeldPartyInstanceCommand"/>): the remote is destroyed and its
/// pinned identity is forgotten, the instance can be approved again. Its result is the number of holders that removed it.
/// </summary>
public interface IRemovePartyInstanceCommand : ICommand<int>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the instance to remove.
    /// </summary>
    string PartyFullName { get; set; }
}

/// <summary>
/// Removes a dynamic instance on the party that holds it: sent by the host of the approval page down the way the instance
/// came up. The holder accepts it only from the host of its "Enlistment" route. Internal to the System.
/// </summary>
[Internal]
public interface IRemoveHeldPartyInstanceCommand : ICommand<bool>
{
    /// <summary>
    /// Gets or sets the full name of the instance to remove.
    /// </summary>
    string PartyFullName { get; set; }
}
