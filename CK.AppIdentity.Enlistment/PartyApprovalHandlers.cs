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
///   On the host of the approval page, the <see cref="IApprovePartyCommand"/>: for each pending approval of the party in
///   the System (see <see cref="EnlistmentItems"/>), a statement signed by the host (and countersigned by the
///   Authentication Center) is sent to its holder: directly, or through the hub of the System.
///   </item>
///   <item>
///   On the holder, the <see cref="IApprovePendingPartyCommand"/>: from the host named in the statement, countersigned by
///   the Authentication Center of the holder (without Authentication Center: only from a direct remote that hosts the
///   approval page, or from itself), with the host's signature when the host is a direct remote; the key of the statement
///   is approved with one of the codes.
///   </item>
/// </list>
/// </summary>
public sealed class PartyApprovalHandlers : ISingletonAutoService
{
    readonly EnlistmentItems _items;
    readonly IPartyApprovalCountersignature? _countersignature;
    readonly bool _missingCountersignature;

    /// <summary>
    /// Initializes the handlers.
    /// </summary>
    /// <param name="items">The items of the approval page.</param>
    /// <param name="countersignature">The countersignature by the Authentication Center, if any.</param>
    /// <param name="proofVerifier">
    /// The verifier of the users' proofs: it exists when the application has an Authentication Center. The countersignature
    /// is then required (CK.AppIdentity.AuthCenter.Enlistment): without it, every approval is refused (fail closed).
    /// </param>
    public PartyApprovalHandlers( EnlistmentItems items,
                                  IPartyApprovalCountersignature? countersignature = null,
                                  ICallerProofVerifier? proofVerifier = null )
    {
        _items = items;
        _countersignature = countersignature;
        _missingCountersignature = countersignature == null && proofVerifier != null;
    }

    // An application that has an Authentication Center and the enlistment must have the countersignature: the holder would
    // otherwise accept an approval from the chain of hops alone.
    bool CheckCountersignature( IActivityMonitor monitor )
    {
        if( !_missingCountersignature ) return true;
        monitor.Error( ActivityMonitor.Tags.SecurityCritical,
                       "This application has an Authentication Center and the enlistment, but not the countersignature of the approvals (CK.AppIdentity.AuthCenter.Enlistment): every approval is refused." );
        return false;
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
    /// Lists the pending approvals of the System (see <see cref="EnlistmentItems"/>), the oldest first.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The query.</param>
    /// <param name="current">The local party: the host of the approval page.</param>
    /// <param name="services">The services of the request.</param>
    /// <param name="pocos">The poco directory.</param>
    /// <returns>The pending approvals (one per holder of a party).</returns>
    [CommandHandler]
    public async Task<IList<IPendingApproval>> HandleAsync( IActivityMonitor monitor,
                                                            IGetPendingApprovalsQCommand command,
                                                            CurrentLocalParty current,
                                                            IServiceProvider services,
                                                            PocoDirectory pocos )
    {
        var held = await _items.GetSystemAsync( monitor, services, current.LocalParty, pocos ).ConfigureAwait( false );
        var result = held.Approvals.ToList();
        result.Sort( ( a, b ) => a.Since.CompareTo( b.Since ) );
        return result;
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
        if( !CheckCountersignature( monitor ) ) return outcomes;
        var held = await _items.GetSystemAsync( monitor, services, host, pocos ).ConfigureAwait( false );
        var keys = host.GetRequiredFeature<ILocalKeys>();
        foreach( var pending in held.Approvals )
        {
            if( pending.PartyFullName != command.PartyFullName ) continue;
            var party = pending.PartyFullName;
            var fingerprint = pending.KeyFingerprint;
            var holder = pending.HolderFullName;
            var statement = pocos.Create<IPartyApprovalStatement>( s =>
            {
                s.PartyFullName = party;
                s.KeyFingerprint = fingerprint;
                s.HolderFullName = holder;
                s.HostFullName = host.FullName;
                s.OperatorActorId = authentication.Actor.ActorId;
                s.Time = host.ApplicationIdentityService.SystemClock.UtcNow;
            } );
            statement.HostSignature = keys.Sign( PartyApprovalStatement.Purpose,
                                                 PartyApprovalStatement.GetSignedData( statement ),
                                                 statement.Time + PartyApprovalStatement.Lifetime ).Encoded.ToArray();
            byte[]? pinGrant = null;
            if( _countersignature != null )
            {
                // A "Both" item: the approved party waits on the holder and must approve it too.
                var (success, countersignature, grant) = await _countersignature.CountersignAsync( monitor, services, host, statement, pending.Kind == "Both" ).ConfigureAwait( false );
                if( !success )
                {
                    monitor.Warn( $"The approval of '{party}' pending on '{holder}' can't be countersigned by the Authentication Center: it is not sent." );
                    outcomes.Add( pocos.Create<IPartyApprovalOutcome>( o =>
                    {
                        o.HolderFullName = holder;
                        o.Status = PartyApprovalStatus.Refused;
                    } ) );
                    continue;
                }
                statement.CenterCountersignature = countersignature;
                pinGrant = grant;
            }
            var approve = pocos.Create<IApprovePendingPartyCommand>( a =>
            {
                a.Statement = statement;
                a.Codes.AddRange( command.Codes );
                a.WaitingPartyGrant = pinGrant;
            } );
            monitor.Info( $"Actor #{statement.OperatorActorId} approves '{party}' (key '{fingerprint}') pending on '{holder}'." );
            PartyApprovalStatus status;
            if( holder == host.FullName.Path )
            {
                // The host holds the pending approval itself.
                status = await ApprovePendingAsync( monitor, host, host.FullName, approve ).ConfigureAwait( false );
            }
            else
            {
                var result = await _items.SendToHolderAsync( monitor, services, host, approve, holder ).ConfigureAwait( false );
                if( result is PartyApprovalStatus s )
                {
                    status = s;
                }
                else
                {
                    monitor.Warn( $"The approval of '{party}' can't reach '{holder}': {result}" );
                    status = PartyApprovalStatus.Unreachable;
                }
            }
            outcomes.Add( pocos.Create<IPartyApprovalOutcome>( o =>
            {
                o.HolderFullName = holder;
                o.Status = status;
            } ) );
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
    /// <param name="authentication">The authentication: its caller party must be the host named in the statement.</param>
    /// <returns>The outcome.</returns>
    [CommandHandler]
    public Task<PartyApprovalStatus> HandleAsync( IActivityMonitor monitor,
                                                  IApprovePendingPartyCommand command,
                                                  CurrentLocalParty current,
                                                  AuthenticationInfo authentication )
    {
        return ApprovePendingAsync( monitor, current.LocalParty, authentication.CallerPartyFullName, command );
    }

    async Task<PartyApprovalStatus> ApprovePendingAsync( IActivityMonitor monitor, ILocalParty holder, string? caller, IApprovePendingPartyCommand command )
    {
        var statement = command.Statement!;
        if( !CheckCountersignature( monitor ) ) return PartyApprovalStatus.Refused;
        // Fail closed: with an Authentication Center, its countersignature (verified below) is the authority of the approval;
        // without, the caller is the holder itself or a direct remote that hosts the approval page of the System.
        if( caller == null
            || (_countersignature == null
                && caller != holder.FullName.Path
                && !holder.Remotes.Any( r => r.FullName.Path == caller && TransportFeatureDriver.GetEnlistmentPageUrl( r.Description, r.FullName ) != null )) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"'{holder.FullName}' refuses the approval of '{statement.PartyFullName}' from '{caller}': it is not an approval page it knows." );
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
        // The countersignature of the Authentication Center: required when the holder has one (fail closed).
        if( _countersignature != null && !await _countersignature.VerifyAsync( monitor, holder, statement ).ConfigureAwait( false ) )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical,
                          $"'{holder.FullName}' refuses the approval of '{statement.PartyFullName}': it is not countersigned by its Authentication Center." );
            return PartyApprovalStatus.Refused;
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
                // The approved party must approve us too: the pin grant of the Authentication Center is handed over to it at
                // its next attempt (it verifies it).
                if( command.WaitingPartyGrant != null )
                {
                    if( issue.Remote != null && AnchoredStatement.TryDecode( command.WaitingPartyGrant, out var grant ) )
                    {
                        issue.Remote.OfferPinGrant( monitor, grant! );
                    }
                    else
                    {
                        monitor.Warn( $"The pin grant of '{statement.PartyFullName}' for '{holder.FullName}' can't be used: it is ignored." );
                    }
                }
                return PartyApprovalStatus.Approved;
            }
            notReady |= codeNotReady;
        }
        return notReady ? PartyApprovalStatus.NotReady : PartyApprovalStatus.CodeMismatch;
    }
}
