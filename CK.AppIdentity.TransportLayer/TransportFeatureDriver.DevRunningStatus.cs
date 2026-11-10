using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Contributes the "Transport" section of the running status of a development party (the "DevRunningStatus" feature
/// of CK.AppIdentity):
/// <list type="bullet">
///     <item>"Listeners": the <see cref="TransportListener.EndPointDescription"/> of the listeners (with the actual listening
///     address when it differs from the configured one).</item>
///     <item>"Remotes": the <see cref="TransportFeature.ConnectionAvailability"/> of each remote that has a transport.</item>
///     <item>"Pending": what an operator must do: for each remote that must accept this party (a peering issue
///     <see cref="PeeringIssueKind.RequiresRemoteApproval"/>, <see cref="PeeringIssueKind.RequiresBothApproval"/> or
///     <see cref="PeeringIssueKind.RequiresRemoteCreation"/>), its enlistment URL and the approval code.</item>
/// </list>
/// The party is ready when every outgoing remote (with a <see cref="TransportFeature.TargetAddress"/>) is
/// <see cref="ConnectionAvailability.Connected"/> or waits for an operator to accept this party (it is "Pending").
/// </summary>
public partial class TransportFeatureDriver : IDevRunningStatusContributor
{
    void IDevRunningStatusContributor.Activate( IActivityMonitor monitor, Action onChanged )
    {
        // The transport feature may be disallowed.
        var transport = ApplicationIdentityService.GetFeature<TransportManagerFeature>();
        if( transport != null )
        {
            transport.ConnectionAvailabilityChanged.Sync += ( m, t ) => onChanged();
            transport.TransportChanged.Sync += ( m, t ) => onChanged();
            transport.PeeringIssueChanged.Sync += ( m, i ) => onChanged();
        }
    }

    bool IDevRunningStatusContributor.IsReady
    {
        get
        {
            var waiting = GetRunningStatusWaitingIssues();
            return GetRunningStatusTransports().All( t => t.TargetAddress == null
                                                          || t.ConnectionAvailability == ConnectionAvailability.Connected
                                                          || waiting.Any( i => i.Remote == t ) );
        }
    }

    // The issues where a remote must accept us: an operator acts, the party is not stuck.
    List<PeeringIssue> GetRunningStatusWaitingIssues()
    {
        return ApplicationIdentityService.GetFeature<TransportManagerFeature>()?
                    .GetClonedPeeringIssues()
                    .Where( i => i.Remote != null
                                 && i.Kind is PeeringIssueKind.RequiresRemoteApproval
                                              or PeeringIssueKind.RequiresBothApproval
                                              or PeeringIssueKind.RequiresRemoteCreation )
                    .ToList()
               ?? [];
    }

    static string GetPendingMessage( PeeringIssue issue )
    {
        var remote = issue.Remote!.Party.FullName.Path;
        var what = issue.EnlistUrl != null ? $"open {issue.EnlistUrl}" : "no approval page is known";
        var code = issue.ApprovalCode != null ? $", the approval code is {issue.ApprovalCode}" : "";
        var both = issue.Kind == PeeringIssueKind.RequiresBothApproval ? " (this party must also approve it, with the same code)" : "";
        return $"'{remote}' must accept this party: {what}{code}{both}.";
    }

    void IDevRunningStatusContributor.Write( Utf8JsonWriter writer )
    {
        var transports = GetRunningStatusTransports().ToList();
        writer.WriteStartObject( "Transport" );
        writer.WriteStartArray( "Listeners" );
        foreach( var l in GetRunningStatusListeners( transports ) )
        {
            writer.WriteStringValue( l.EndPointDescription );
        }
        writer.WriteEndArray();
        writer.WriteStartArray( "Remotes" );
        foreach( var t in transports )
        {
            writer.WriteStartObject();
            writer.WriteString( "FullName", t.Party.FullName.Path );
            writer.WriteString( "Availability", t.ConnectionAvailability.ToString() );
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        var waiting = GetRunningStatusWaitingIssues();
        if( waiting.Count > 0 )
        {
            writer.WriteStartArray( "Pending" );
            foreach( var i in waiting ) writer.WriteStringValue( GetPendingMessage( i ) );
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }

    IEnumerable<TransportFeature> GetRunningStatusTransports() => ApplicationIdentityService.AllRemotes.Select( r => r.GetFeature<TransportFeature>() ).Where( t => t != null )!;

    // The listeners of the remotes, and the "AlwaysListening" ones of the local parties.
    IEnumerable<TransportListener> GetRunningStatusListeners( List<TransportFeature> transports )
    {
        var s = ApplicationIdentityService;
        var alwaysListening = s.TenantDomains.Cast<ILocalParty>()
                                             .Prepend( s )
                                             .SelectMany( l => l.GetFeature<TransportListener[]>() ?? [] );
        return transports.SelectMany( t => t.Listeners ?? [] )
                         .Concat( alwaysListening )
                         .Distinct();
    }
}
