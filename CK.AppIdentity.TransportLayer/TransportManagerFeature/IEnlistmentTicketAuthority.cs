using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The holder of the pre-authorized enlistment tickets (see <see cref="EnlistTicket"/>): the Authentication Center of the
/// System. A party that starts with a ticket proves it in its initial message; the holder that recognizes the proof
/// trusts its key at once (no approval code, no pending approval). While a ticket is open for a party, a key presented
/// without a valid proof is refused: strangers can't block the enlistment of an expected party.
/// Without this service, or for a local party that holds no ticket, the enlistment is unchanged.
/// </summary>
public interface IEnlistmentTicketAuthority : ISingletonAutoService
{
    /// <summary>
    /// Gets whether a local party holds an open ticket (not used, not expired) for a party.
    /// </summary>
    /// <param name="local">The local party (the holder).</param>
    /// <param name="partyFullName">The full name of the expected party.</param>
    /// <returns>True when a ticket is open for it.</returns>
    bool HasOpenTicket( ILocalParty local, string partyFullName );

    /// <summary>
    /// Verifies a proof of a ticket (see <see cref="EnlistTicket.VerifyProof"/>) and, when it is valid for an open ticket
    /// of the party, uses the ticket: it is closed and records the key it enlisted.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="local">The local party (the holder).</param>
    /// <param name="partyFullName">The full name of the party.</param>
    /// <param name="proof">The proof.</param>
    /// <param name="identity">The checkpoint of the head of the key event log of the party.</param>
    /// <param name="keyFingerprint">The fingerprint of the key it enlists.</param>
    /// <param name="ephemeralPublicKey">The ephemeral public key of the connection.</param>
    /// <returns>True when the ticket is valid and has been used: the key is trusted.</returns>
    bool TryUse( IParallelLogger logger,
                 ILocalParty local,
                 string partyFullName,
                 ReadOnlySpan<byte> proof,
                 KeyCheckpoint identity,
                 string keyFingerprint,
                 ReadOnlySpan<byte> ephemeralPublicKey );

    /// <summary>
    /// Opens a ticket on a holder, its key created here: the text of the ticket, or null when the local party holds no
    /// tickets (the reason is logged). For "ckey ticket open" on the center (the approval page creates the key on its
    /// host and uses <see cref="Register"/>).
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="local">The holder.</param>
    /// <param name="partyFullName">The full name of the expected party.</param>
    /// <param name="lifetime">The lifetime of the ticket.</param>
    /// <param name="operatorActorId">The operator (0 for a local operator: ckey).</param>
    /// <returns>The text of the ticket (a secret), or null.</returns>
    string? Open( IActivityMonitor monitor, ILocalParty local, string partyFullName, TimeSpan lifetime, int operatorActorId );

    /// <summary>
    /// Registers a ticket whose key was created elsewhere (the host of the approval page): its public key only. Returns
    /// the checkpoint of the holder (the anchor that the ticket carries), or null when it is refused (logged).
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="local">The holder.</param>
    /// <param name="ticketId">The id of the ticket (<see cref="EnlistTicket.IdText"/>).</param>
    /// <param name="partyFullName">The full name of the expected party.</param>
    /// <param name="publicKey">The public key of the ticket (SubjectPublicKeyInfo).</param>
    /// <param name="expires">The expiration (UTC).</param>
    /// <param name="operatorActorId">The operator.</param>
    /// <returns>The checkpoint of the holder, or null.</returns>
    KeyCheckpoint? Register( IActivityMonitor monitor, ILocalParty local, string ticketId, string partyFullName, byte[] publicKey, DateTime expires, int operatorActorId );

    /// <summary>
    /// Gets the tickets of a holder: the open ones and the used ones (the expired ones are forgotten after a while).
    /// </summary>
    /// <param name="local">The holder.</param>
    /// <returns>The tickets.</returns>
    IReadOnlyList<EnlistmentTicketInfo> GetTickets( ILocalParty local );

    /// <summary>
    /// Revokes (forgets) a ticket of a holder.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="local">The holder.</param>
    /// <param name="ticketId">The ticket id.</param>
    /// <returns>True when it existed.</returns>
    bool Revoke( IActivityMonitor monitor, ILocalParty local, string ticketId );
}

/// <summary>
/// A ticket held by a holder (see <see cref="IEnlistmentTicketAuthority.GetTickets"/>).
/// </summary>
/// <param name="Id">The ticket id.</param>
/// <param name="PartyFullName">The full name of the expected party.</param>
/// <param name="Opened">When it was opened.</param>
/// <param name="Expires">Its expiration.</param>
/// <param name="OperatorActorId">The operator who opened it (0 for a local operator).</param>
/// <param name="Used">When it was used, null while it is open.</param>
/// <param name="UsedByFingerprint">The fingerprint of the key it enlisted, null while it is open.</param>
public sealed record EnlistmentTicketInfo( string Id,
                                           string PartyFullName,
                                           DateTime Opened,
                                           DateTime Expires,
                                           int OperatorActorId,
                                           DateTime? Used,
                                           string? UsedByFingerprint );
