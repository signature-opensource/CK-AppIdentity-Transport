using CK.AppIdentity.Cris;
using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.AppIdentity.Enlistment;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Enlistment;

/// <summary>
/// Handles the approval of a pending party:
/// <list type="bullet">
///   <item>
///   On the host of the approval page, the <see cref="IApprovePartyCommand"/>: for each pending approval of the party
///   collected along the "Enlistment" route (see <see cref="PartyDescription.Collected"/>), a statement signed by the host
///   is sent down to its holder by the reversed path of the item (an <see cref="IPartyRoutedCommand"/>).
///   </item>
///   <item>
///   On the holder, the <see cref="IApprovePendingPartyCommand"/>: accepted only from the host of its "Enlistment" route,
///   with the host's signature when the host is a direct remote; the key of the statement is approved with one of the codes.
///   </item>
/// </list>
/// </summary>
public sealed class PartyApprovalHandlers : ISingletonAutoService
{
    readonly PartyRoutedCommandSender _sender;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="sender">The sender of the routed commands.</param>
    public PartyApprovalHandlers( PartyRoutedCommandSender sender )
    {
        _sender = sender;
    }

    /// <summary>
    /// Refuses an approval made while impersonating: the operator approves as itself.
    /// </summary>
    /// <param name="c">The message collector.</param>
    /// <param name="command">The command.</param>
    /// <param name="authentication">The authentication.</param>
    [CommandHandlingValidator]
    public void Validate( UserMessageCollector c, IApprovePartyCommand command, AuthenticationInfo authentication )
    {
        if( authentication.IsImpersonated )
        {
            c.Error( "A party can't be approved while impersonating.", "AppIdentity.Enlistment.Impersonated" );
        }
    }

    /// <summary>
    /// Sends the approval of a party to every party that holds a pending approval of it.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party: the host of the approval page.</param>
    /// <param name="authentication">The authentication of the operator.</param>
    /// <param name="services">The services of the scope.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>An outcome per holder (empty when no party holds a pending approval of the party).</returns>
    [CommandHandler]
    public async Task<IList<IPartyApprovalOutcome>> HandleAsync( IActivityMonitor monitor,
                                                                 IApprovePartyCommand command,
                                                                 CurrentLocalParty current,
                                                                 AuthenticationInfo authentication,
                                                                 IServiceProvider services,
                                                                 PocoDirectory pocos )
    {
        var host = current.LocalParty;
        var outcomes = new List<IPartyApprovalOutcome>();
        if( host.Description.Collected.TryGetValue( TransportFeatureDriver.EnlistmentRouteName, out var items ) )
        {
            var keys = host.GetRequiredFeature<ILocalKeys>();
            foreach( var item in items )
            {
                if( !TransportFeatureDriver.TryReadPendingApprovalValue( item.Value, out var party, out var fingerprint )
                    || party != command.PartyFullName )
                {
                    continue;
                }
                var statement = pocos.Create<IPartyApprovalStatement>( s =>
                {
                    s.PartyFullName = party;
                    s.KeyFingerprint = fingerprint;
                    s.HolderFullName = item.Holder;
                    s.HostFullName = host.FullName;
                    s.OperatorActorId = authentication.Actor.ActorId;
                    s.Time = host.ApplicationIdentityService.SystemClock.UtcNow;
                } );
                statement.HostSignature = keys.Sign( PartyApprovalStatement.Purpose,
                                                     PartyApprovalStatement.GetSignedData( statement ),
                                                     statement.Time + PartyApprovalStatement.Lifetime ).Encoded.ToArray();
                var approve = pocos.Create<IApprovePendingPartyCommand>( a =>
                {
                    a.Statement = statement;
                    a.Codes.AddRange( command.Codes );
                } );
                monitor.Info( $"Actor #{statement.OperatorActorId} approves '{party}' (key '{fingerprint}') pending on '{item.Holder}'." );
                PartyApprovalStatus status;
                if( item.Length == 1 )
                {
                    // The host holds the pending approval itself.
                    status = ApprovePending( monitor, host, host.FullName, approve );
                }
                else
                {
                    var result = await _sender.SendAlongPathAsync( monitor, services, host, approve, item.Path.Reverse() ).ConfigureAwait( false );
                    if( result is PartyApprovalStatus s )
                    {
                        status = s;
                    }
                    else
                    {
                        monitor.Warn( $"The approval of '{party}' can't reach '{item.Holder}': {result}" );
                        status = PartyApprovalStatus.Unreachable;
                    }
                }
                outcomes.Add( pocos.Create<IPartyApprovalOutcome>( o =>
                {
                    o.HolderFullName = item.Holder;
                    o.Status = status;
                } ) );
            }
        }
        if( outcomes.Count == 0 ) monitor.Warn( $"No pending approval of '{command.PartyFullName}' is known by '{host.FullName}'." );
        return outcomes;
    }

    /// <summary>
    /// Approves the key of the statement with one of the codes, on the party that holds the pending approval.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command.</param>
    /// <param name="current">The local party: the holder.</param>
    /// <param name="authentication">The authentication: its caller party must be the host of the "Enlistment" route.</param>
    /// <returns>The outcome.</returns>
    [CommandHandler]
    public PartyApprovalStatus Handle( IActivityMonitor monitor,
                                       IApprovePendingPartyCommand command,
                                       CurrentLocalParty current,
                                       AuthenticationInfo authentication )
    {
        return ApprovePending( monitor, current.LocalParty, authentication.CallerPartyFullName, command );
    }

    static PartyApprovalStatus ApprovePending( IActivityMonitor monitor, ILocalParty holder, string? caller, IApprovePendingPartyCommand command )
    {
        var statement = command.Statement!;
        // Fail closed: only from the host of the route, about a pending approval of this holder.
        holder.Description.Routes.TryGetValue( TransportFeatureDriver.EnlistmentRouteName, out var route );
        if( caller == null || route == null || route.Host != caller )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"'{holder.FullName}' refuses the approval of '{statement.PartyFullName}' from '{caller}': it is not the host of its \"Enlistment\" route ({route?.Host ?? "none"})." );
            return PartyApprovalStatus.Refused;
        }
        if( statement.HostFullName != caller || statement.HolderFullName != holder.FullName )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"'{holder.FullName}' refuses the approval of '{statement.PartyFullName}' from '{caller}': the statement is about the host '{statement.HostFullName}' and the holder '{statement.HolderFullName}'." );
            return PartyApprovalStatus.Refused;
        }
        // The host's signature is checked when its keys are known here (the host itself or a direct remote). Otherwise
        // the approval is accepted from the chain of hops, each one authenticated by the next.
        IPartyKeys? hostKeys = caller == holder.FullName
                                ? holder.GetFeature<IPartyKeys>()
                                : holder.Remotes.FirstOrDefault( r => r.FullName == caller )?.GetFeature<IPartyKeys>();
        if( hostKeys != null )
        {
            if( !ApplicationSignature.TryRead( statement.HostSignature, out var signature )
                || hostKeys.Check( monitor, PartyApprovalStatement.Purpose, PartyApprovalStatement.GetSignedData( statement ), signature ) != SignatureVerdict.Valid )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                              $"'{holder.FullName}' refuses the approval of '{statement.PartyFullName}': the signature of '{caller}' is invalid." );
                return PartyApprovalStatus.Refused;
            }
        }
        else
        {
            monitor.Trace( $"The approval of '{statement.PartyFullName}' is accepted from the chain of hops: the keys of '{caller}' are not known by '{holder.FullName}'." );
        }
        var issue = holder.ApplicationIdentityService.GetRequiredFeature<TransportManagerFeature>()
                          .GetPeeringIssues()
                          .FirstOrDefault( i => i.FullName == statement.PartyFullName && i.Remote?.Party.Owner == holder && i.CanAcceptRemoteIdentity );
        if( issue == null )
        {
            monitor.Warn( $"'{holder.FullName}' has no pending approval of '{statement.PartyFullName}'." );
            return PartyApprovalStatus.NoPendingApproval;
        }
        bool notReady = false;
        foreach( var code in command.Codes )
        {
            if( issue.TryApprove( monitor, code, statement.KeyFingerprint, out var codeNotReady ) )
            {
                // The audit of the enlistment.
                monitor.Info( ActivityMonitor.Tags.SecurityCritical,
                              $"'{holder.FullName}' approved '{statement.PartyFullName}' (key '{statement.KeyFingerprint}'), approved by actor " +
                              $"#{statement.OperatorActorId} on '{statement.HostFullName}' at {statement.Time:O}, " +
                              $"signature: {Convert.ToBase64String( statement.HostSignature )}." );
                return PartyApprovalStatus.Approved;
            }
            notReady |= codeNotReady;
        }
        return notReady ? PartyApprovalStatus.NotReady : PartyApprovalStatus.CodeMismatch;
    }
}
