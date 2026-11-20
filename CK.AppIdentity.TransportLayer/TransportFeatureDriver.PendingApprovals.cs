using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// What a local party holds for the approval page of the System: its pending approvals and the approved dynamic
/// instances of its Opened remote templates. They are asked, never announced (CK.AppIdentity.Enlistment asks them
/// through the hub of the System, its Authentication Center).
/// </summary>
public partial class TransportFeatureDriver
{
    /// <summary>
    /// Gets the pending approvals held by a local party: a <see cref="PeeringIssueKind.RequiresLocalApproval"/> or
    /// <see cref="PeeringIssueKind.RequiresBothApproval"/> issue with one of its remotes. Never the approval code: the
    /// operator reads it on the party to approve.
    /// </summary>
    /// <param name="party">The local party (the holder).</param>
    /// <returns>The pending approvals.</returns>
    public static IReadOnlyList<PendingApprovalValue> GetHeldPendingApprovals( ILocalParty party )
    {
        Throw.CheckNotNullArgument( party );
        if( party.ApplicationIdentityService.GetFeature<TransportManagerFeature>() is not { } transport ) return [];
        var result = new List<PendingApprovalValue>();
        foreach( var issue in transport.GetClonedPeeringIssues() )
        {
            if( issue.Remote?.Party.Owner != party ) continue;
            var since = issue.ApprovalPendingSince;
            var fingerprint = issue.RemoteKeyFingerprintForApproval;
            if( since == null || fingerprint == null ) continue;
            result.Add( new PendingApprovalValue( issue.FullName,
                                                  party.FullName,
                                                  fingerprint,
                                                  issue.Kind == PeeringIssueKind.RequiresBothApproval ? "Both" : "Local",
                                                  since.Value.ToUniversalTime(),
                                                  issue.Remote?.Party.Configuration is { IsDynamicInstance: true } c ? c.Template!.PartyNamePattern : null,
                                                  issue.Remote?.Approval.CompetingKeyCount is int competing && competing > 1 ? competing : 1 ) );
        }
        return result;
    }

    /// <summary>
    /// Gets the approved dynamic instances of the Opened remote templates of a local party (their identity is pinned):
    /// the approval page can remove them.
    /// </summary>
    /// <param name="party">The local party (the holder).</param>
    /// <returns>The instances.</returns>
    public static IReadOnlyList<PartyInstanceValue> GetHeldPartyInstances( ILocalParty party )
    {
        Throw.CheckNotNullArgument( party );
        return party.Remotes.Where( r => !r.IsDestroyed
                                         && r.Configuration.IsDynamicInstance
                                         && r.GetFeature<TransportFeature>() is { } t
                                         && t.RemoteKeys.TrustedEvent != null )
                            .Select( r => new PartyInstanceValue( r.FullName.Path, party.FullName, r.Configuration.Template!.PartyNamePattern ) )
                            .ToList();
    }
}

/// <summary>
/// A pending approval held by a local party (see <see cref="TransportFeatureDriver.GetHeldPendingApprovals"/>).
/// </summary>
/// <param name="PartyFullName">The full name of the party to approve.</param>
/// <param name="HolderFullName">The full name of the party that holds the pending approval.</param>
/// <param name="Fingerprint">The fingerprint of the key to approve.</param>
/// <param name="Kind">"Local", or "Both" when the party to approve must also approve the holder.</param>
/// <param name="Since">Since when the key waits (UTC).</param>
/// <param name="TemplatePartyName">The party name of the Opened template of a candidate, null when the party is not a dynamic instance.</param>
/// <param name="CompetingKeyCount">The number of keys that compete for the approval of the party (1 when there is no competition).</param>
public sealed record PendingApprovalValue( string PartyFullName,
                                           string HolderFullName,
                                           string Fingerprint,
                                           string Kind,
                                           DateTime Since,
                                           string? TemplatePartyName = null,
                                           int CompetingKeyCount = 1 );

/// <summary>
/// An approved dynamic instance of an Opened remote template held by a local party (see
/// <see cref="TransportFeatureDriver.GetHeldPartyInstances"/>).
/// </summary>
/// <param name="PartyFullName">The full name of the instance.</param>
/// <param name="HolderFullName">The full name of the party that holds it.</param>
/// <param name="TemplatePartyName">The party name of its template: "$Worker-{Name}".</param>
public sealed record PartyInstanceValue( string PartyFullName, string HolderFullName, string TemplatePartyName );
