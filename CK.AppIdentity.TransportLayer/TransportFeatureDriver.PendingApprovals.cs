using CK.Core;
using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The pending approvals of the local parties travel the "Enlistment" route toward the approval page of the System: they
/// are items collected along it (see <see cref="PartyDescription.Collected"/>).
/// </summary>
public partial class TransportFeatureDriver
{
    // A peering issue changed: the pending approvals of its local party may have changed.
    Task OnPeeringIssueChangedAsync( IActivityMonitor monitor, PeeringIssue issue, CancellationToken cancel )
    {
        return OnDescriptionChangedAsync( monitor, issue.Remote?.Party.Owner );
    }

    /// <summary>
    /// States the pending approvals of the local party (a <see cref="PeeringIssueKind.RequiresLocalApproval"/> or
    /// <see cref="PeeringIssueKind.RequiresBothApproval"/> issue with one of its remotes) as items to collect along the
    /// <see cref="EnlistmentRouteName"/> route (see <see cref="GetPendingApprovalValue"/>).
    /// </summary>
    /// <param name="party">The local party.</param>
    /// <param name="builder">The first phase of its description.</param>
    protected override void ContributeDescription( ILocalParty party, PartyDescription.Builder builder )
    {
        if( _transportManager == null ) return;
        foreach( var issue in _transportManager.Feature.GetClonedPeeringIssues() )
        {
            if( issue.Remote?.Party.Owner != party ) continue;
            var value = GetPendingApprovalValue( issue );
            if( value == null ) continue;
            if( value.Length <= CollectedItem.MaxValueLength ) builder.Collect( EnlistmentRouteName, value );
            else ActivityMonitor.StaticLogger.Warn( $"The pending approval of '{issue.FullName}' by '{party.FullName}' is too long to be collected." );
        }
    }

    /// <summary>
    /// Gets the value of a pending approval, as collected along the <see cref="EnlistmentRouteName"/> route: an opaque JSON
    /// object <c>{ "Party": the full name of the party to approve, "Fingerprint": the fingerprint of the key to approve,
    /// "Kind": "Local" or "Both", "Since": when the key started to wait (ISO 8601, UTC) }</c>. Never the approval code: the
    /// operator reads it on the party to approve. The holder of the approval is the first party of the item's path.
    /// </summary>
    /// <param name="issue">The peering issue.</param>
    /// <returns>The value, or null when the issue is not a pending approval.</returns>
    public static string? GetPendingApprovalValue( PeeringIssue issue )
    {
        Throw.CheckNotNullArgument( issue );
        var since = issue.ApprovalPendingSince;
        var fingerprint = issue.RemoteKeyFingerprintForApproval;
        if( since == null || fingerprint == null ) return null;
        var buffer = new ArrayBufferWriter<byte>();
        using( var w = new Utf8JsonWriter( buffer ) )
        {
            w.WriteStartObject();
            w.WriteString( "Party", issue.FullName );
            w.WriteString( "Fingerprint", fingerprint );
            w.WriteString( "Kind", issue.Kind == PeeringIssueKind.RequiresBothApproval ? "Both" : "Local" );
            w.WriteString( "Since", since.Value );
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString( buffer.WrittenSpan );
    }
}
