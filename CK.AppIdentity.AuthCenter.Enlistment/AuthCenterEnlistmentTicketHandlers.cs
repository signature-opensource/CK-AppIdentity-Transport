using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Enlistment;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter.Enlistment;

/// <summary>
/// Registers on the Authentication Center an enlistment ticket opened on the host of the approval page (see
/// <see cref="IOpenEnlistmentTicketCommand"/>): its public key only, the key never leaves the host. The center checks it
/// like a countersignature (the operator's live proof at the Critical level, not impersonated, sent by a party) and
/// returns its checkpoint: the anchor the ticket carries.
/// </summary>
[Internal]
public interface IRegisterEnlistmentTicketCommand : ICommand<string?>, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the ticket id.
    /// </summary>
    string TicketId { get; set; }

    /// <summary>
    /// Gets or sets the full name of the expected party.
    /// </summary>
    string PartyFullName { get; set; }

    /// <summary>
    /// Gets or sets the public key of the ticket (SubjectPublicKeyInfo).
    /// </summary>
    byte[] PublicKey { get; set; }

    /// <summary>
    /// Gets or sets the expiration of the ticket.
    /// </summary>
    DateTime Expires { get; set; }
}

/// <summary>
/// The handlers of the enlistment tickets (see <see cref="AuthCenterEnlistmentTickets"/>): the key of a ticket is created
/// on the host of the approval page and its public key registered on the Authentication Center (here, or sent to it: it is
/// a remote of the host); the tickets are listed and revoked on the center.
/// </summary>
public sealed class AuthCenterEnlistmentTicketHandlers : ISingletonAutoService
{
    readonly AuthCenterEnlistmentTickets _tickets;
    readonly PartyRoutedCommandSender _sender;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="tickets">The tickets of the center.</param>
    /// <param name="sender">The sender of the routed commands.</param>
    public AuthCenterEnlistmentTicketHandlers( AuthCenterEnlistmentTickets tickets, PartyRoutedCommandSender sender )
    {
        _tickets = tickets;
        _sender = sender;
    }

    /// <summary>
    /// Opens a ticket: its key is created here, its public key registered on the center, the ticket returned once.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The host.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <param name="services">The services (to send routed commands).</param>
    /// <returns>The ticket, or null when it is refused (the reason is logged).</returns>
    [CommandHandler]
    public async Task<IEnlistmentTicket?> HandleAsync( IActivityMonitor monitor,
                                                       IOpenEnlistmentTicketCommand command,
                                                       CurrentLocalParty current,
                                                       AuthenticationInfo authentication,
                                                       PocoDirectory pocos,
                                                       IServiceProvider services )
    {
        var host = current.LocalParty;
        var center = host.GetFeature<CrisAuthCenter>();
        if( center == null )
        {
            monitor.Warn( $"'{host}' has no Authentication Center: it can't open an enlistment ticket." );
            return null;
        }
        if( authentication.IsImpersonated )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"An impersonating operator can't open an enlistment ticket on '{host}'." );
            return null;
        }
        var lifetime = AuthCenterEnlistmentTickets.ClampLifetime( TimeSpan.FromHours( command.LifetimeHours ) );
        var expires = host.ApplicationIdentityService.SystemClock.UtcNow + lifetime;
        var key = EnlistTicket.CreateKey( out var id );
        try
        {
            var idText = Convert.ToHexStringLower( id );
            KeyCheckpoint? checkpoint;
            if( center.AuthCenter == host )
            {
                checkpoint = _tickets.Register( monitor, host, idText, command.PartyFullName, key.ExportSubjectPublicKeyInfo(), expires, authentication.Actor.ActorId );
            }
            else
            {
                var register = pocos.Create<IRegisterEnlistmentTicketCommand>( c =>
                {
                    c.ActorId = authentication.Actor.ActorId;
                    c.TicketId = idText;
                    c.PartyFullName = command.PartyFullName;
                    c.PublicKey = key.ExportSubjectPublicKeyInfo();
                    c.Expires = expires;
                } );
                var result = await SendToCenterAsync( monitor, services, host, center, register, "register the enlistment ticket of " + command.PartyFullName ).ConfigureAwait( false );
                checkpoint = result is string s && KeyCheckpoint.TryParse( s, out var c, out _ ) ? c : null;
            }
            if( checkpoint == null ) return null;
            using var ticket = EnlistTicket.Create( id, key, center.AuthCenterFullName, checkpoint, expires );
            key = null;
            return pocos.Create<IEnlistmentTicket>( t =>
            {
                t.Id = ticket.IdText;
                t.Ticket = ticket.Encode();
                t.Expires = expires;
            } );
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <summary>
    /// Registers a ticket on the Authentication Center (sent by the host of the approval page).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party: the center.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <returns>The checkpoint of the center, or null when it is refused (the reason is logged).</returns>
    [CommandHandler]
    public string? Handle( IActivityMonitor monitor, IRegisterEnlistmentTicketCommand command, CurrentLocalParty current, AuthenticationInfo authentication )
    {
        var center = current.LocalParty;
        string? refusal = null;
        if( center.GetFeature<CrisAuthCenter>()?.AuthCenter != center ) refusal = "it is not an Authentication Center";
        else if( authentication.IsImpersonated ) refusal = "the operator is impersonating";
        else if( authentication.ActualActor.Level < AuthLevel.Critical ) refusal = "the operator is not at the Critical level";
        else if( authentication.CallerPartyFullName == null ) refusal = "it is not sent by a party";
        if( refusal != null )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"'{center}' refuses the enlistment ticket of '{command.PartyFullName}': {refusal}." );
            return null;
        }
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"'{authentication.CallerPartyFullName}' registers an enlistment ticket of '{command.PartyFullName}' on '{center}'." );
        return _tickets.Register( monitor, center, command.TicketId, command.PartyFullName, command.PublicKey, command.Expires, authentication.Actor.ActorId )?.ToString();
    }

    /// <summary>
    /// Lists the tickets of the Authentication Center (forwarded to it when the local party is not the center).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <param name="services">The services (to send routed commands).</param>
    /// <returns>The tickets.</returns>
    [CommandHandler]
    public async Task<IList<IEnlistmentTicketInfo>> HandleAsync( IActivityMonitor monitor,
                                                                 IGetEnlistmentTicketsQCommand command,
                                                                 CurrentLocalParty current,
                                                                 AuthenticationInfo authentication,
                                                                 PocoDirectory pocos,
                                                                 IServiceProvider services )
    {
        var local = current.LocalParty;
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null || authentication.IsImpersonated ) return [];
        if( center.AuthCenter == local )
        {
            return _tickets.GetTickets( local ).Select( t => pocos.Create<IEnlistmentTicketInfo>( i =>
            {
                i.Id = t.Id;
                i.PartyFullName = t.PartyFullName;
                i.Opened = t.Opened;
                i.Expires = t.Expires;
                i.OperatorActorId = t.OperatorActorId;
                i.Used = t.Used;
                i.UsedByFingerprint = t.UsedByFingerprint;
            } ) ).ToList();
        }
        command.ActorId = authentication.Actor.ActorId;
        var result = await SendToCenterAsync( monitor, services, local, center, command, "list the enlistment tickets" ).ConfigureAwait( false );
        return result as IList<IEnlistmentTicketInfo> ?? [];
    }

    /// <summary>
    /// Revokes a ticket of the Authentication Center (forwarded to it when the local party is not the center).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="services">The services (to send routed commands).</param>
    /// <returns>True when the ticket existed.</returns>
    [CommandHandler]
    public async Task<bool> HandleAsync( IActivityMonitor monitor,
                                         IRevokeEnlistmentTicketCommand command,
                                         CurrentLocalParty current,
                                         AuthenticationInfo authentication,
                                         IServiceProvider services )
    {
        var local = current.LocalParty;
        var center = local.GetFeature<CrisAuthCenter>();
        if( center == null || authentication.IsImpersonated ) return false;
        if( center.AuthCenter == local ) return _tickets.Revoke( monitor, local, command.TicketId );
        command.ActorId = authentication.Actor.ActorId;
        return await SendToCenterAsync( monitor, services, local, center, command, "revoke an enlistment ticket" ).ConfigureAwait( false ) is true;
    }

    // Sends a command to the Authentication Center (a remote of the local party). The operator's proof travels with it,
    // sealed. Null when it can't be sent or is refused (the reason is logged).
    async Task<object?> SendToCenterAsync( IActivityMonitor monitor, IServiceProvider services, ILocalParty local, CrisAuthCenter center, IAbstractCommand command, string what )
    {
        object? result;
        try
        {
            result = await _sender.SendToAsync( monitor, services, local, command, center.AuthCenterFullName ).ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Warn( $"Unable to ask the AuthCenter '{center.AuthCenterFullName}' to {what}.", ex );
            return null;
        }
        if( result is ICrisResultError e )
        {
            monitor.Warn( $"The AuthCenter '{center.AuthCenterFullName}' doesn't {what}: {e.Errors.Select( m => m.Text ).Concatenate()}" );
            return null;
        }
        return result;
    }
}
