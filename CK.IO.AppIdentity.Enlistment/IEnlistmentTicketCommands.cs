using CK.Auth;
using CK.Core;
using CK.Cris;
using System;
using System.Collections.Generic;

namespace CK.IO.AppIdentity.Enlistment;

/// <summary>
/// Opens a pre-authorized enlistment ticket for an expected party: sent by the approval page, the operator expects a
/// party ("$Worker-3") that will start with the ticket. The ticket is held by the Authentication Center of the System;
/// the party proves it when it connects to the center and its key is trusted at once (no approval code). While the ticket
/// is open, a key presented under this name without it is refused. The result is the only copy of the ticket: it is a
/// secret, given to the party at start ("Local:KeyManagement:EnlistTicket").
/// </summary>
public interface IOpenEnlistmentTicketCommand : ICommand<IEnlistmentTicket?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the full name of the expected party.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the lifetime of the ticket, in hours: 24 when 0, at most 168 (7 days).
    /// </summary>
    int LifetimeHours { get; set; }
}

/// <summary>
/// A ticket opened by <see cref="IOpenEnlistmentTicketCommand"/>.
/// </summary>
public interface IEnlistmentTicket : IPoco
{
    /// <summary>
    /// Gets or sets the ticket id.
    /// </summary>
    string Id { get; set; }

    /// <summary>
    /// Gets or sets the text of the ticket: a secret, to give to the party.
    /// </summary>
    string Ticket { get; set; }

    /// <summary>
    /// Gets or sets the expiration of the ticket.
    /// </summary>
    DateTime Expires { get; set; }
}

/// <summary>
/// Gets the enlistment tickets of the Authentication Center: the open ones and the used ones.
/// </summary>
public interface IGetEnlistmentTicketsQCommand : ICommand<IList<IEnlistmentTicketInfo>>, ICommandAuthCritical
{
}

/// <summary>
/// An enlistment ticket held by the Authentication Center (never its key: only the center's public data).
/// </summary>
public interface IEnlistmentTicketInfo : IPoco
{
    /// <summary>
    /// Gets or sets the ticket id.
    /// </summary>
    string Id { get; set; }

    /// <summary>
    /// Gets or sets the full name of the expected party.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets when the ticket was opened.
    /// </summary>
    DateTime Opened { get; set; }

    /// <summary>
    /// Gets or sets the expiration of the ticket.
    /// </summary>
    DateTime Expires { get; set; }

    /// <summary>
    /// Gets or sets the operator who opened it (0 for a local operator: ckey).
    /// </summary>
    int OperatorActorId { get; set; }

    /// <summary>
    /// Gets or sets when the ticket was used, null while it is open.
    /// </summary>
    DateTime? Used { get; set; }

    /// <summary>
    /// Gets or sets the fingerprint of the key the ticket enlisted, null while it is open.
    /// </summary>
    string? UsedByFingerprint { get; set; }
}

/// <summary>
/// Revokes (forgets) an enlistment ticket of the Authentication Center.
/// </summary>
public interface IRevokeEnlistmentTicketCommand : ICommand<bool>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the ticket id.
    /// </summary>
    string TicketId { get; set; }
}
