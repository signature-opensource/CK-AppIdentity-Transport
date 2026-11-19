using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Asks a party which of its remotes accept a command (<see cref="CrisChannelFeature.AcceptedCommands"/>, advertised by
/// their channels): the directory of the System when it is asked to its hub (see <see cref="IPartyRelay"/>). A party
/// command: its target answers for its own remotes. Internal to the System.
/// </summary>
[Internal]
public interface IGetAcceptingRemotesQCommand : ICommand<IList<string>>, ICommandTargetParty
{
    /// <summary>
    /// Gets or sets the name of the command (its <c>CrisPocoModel.PocoName</c>).
    /// </summary>
    string CommandName { get; set; }
}

/// <summary>
/// Answers the <see cref="IGetAcceptingRemotesQCommand"/>: the full names of the remotes of the local party whose channel
/// accepts the command (a remote that has not advertised its commands yet is not listed).
/// </summary>
public sealed class AcceptingRemotesHandler : ISingletonAutoService
{
    /// <summary>
    /// Lists the remotes of the local party that accept a command.
    /// </summary>
    /// <param name="command">The query.</param>
    /// <param name="party">The local party (the target of the query).</param>
    /// <returns>The full names of the remotes, in the ordinal order.</returns>
    [CommandHandler]
    public IList<string> Handle( IGetAcceptingRemotesQCommand command, CurrentLocalParty party )
    {
        return party.LocalParty.Remotes
                    .Where( r => r.GetFeature<CrisChannelFeature>()?.AcceptedCommands?.Contains( command.CommandName ) is true )
                    .Select( r => r.FullName.Path )
                    .Order( StringComparer.Ordinal )
                    .ToList();
    }
}
