using CK.Core;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
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

    /// <summary>
    /// Reads the value of a pending approval (see <see cref="GetPendingApprovalValue"/>).
    /// </summary>
    /// <param name="value">The value of the collected item.</param>
    /// <param name="approval">The pending approval on success.</param>
    /// <returns>True on success, false when the value is not a pending approval.</returns>
    public static bool TryReadPendingApprovalValue( string value, [NotNullWhen( true )] out PendingApprovalValue? approval )
    {
        approval = null;
        try
        {
            using var doc = JsonDocument.Parse( value );
            var e = doc.RootElement;
            if( e.ValueKind == JsonValueKind.Object
                && e.TryGetProperty( "Party", out var p ) && p.ValueKind == JsonValueKind.String && p.GetString() is { Length: > 0 } party
                && e.TryGetProperty( "Fingerprint", out var f ) && f.ValueKind == JsonValueKind.String && f.GetString() is { Length: > 0 } fingerprint
                && e.TryGetProperty( "Kind", out var k ) && k.ValueKind == JsonValueKind.String && k.GetString() is "Local" or "Both"
                && e.TryGetProperty( "Since", out var t ) && t.ValueKind == JsonValueKind.String && t.TryGetDateTime( out var since ) )
            {
                approval = new PendingApprovalValue( party, fingerprint, k.GetString()!, since.ToUniversalTime() );
                return true;
            }
        }
        catch( JsonException )
        {
        }
        return false;
    }
}

/// <summary>
/// The value of a pending approval collected along the "Enlistment" route (see
/// <see cref="TransportFeatureDriver.GetPendingApprovalValue"/>): the holder of the approval is the first party of the path
/// of the item.
/// </summary>
/// <param name="PartyFullName">The full name of the party to approve.</param>
/// <param name="Fingerprint">The fingerprint of the key to approve.</param>
/// <param name="Kind">"Local", or "Both" when the party to approve must also approve the holder.</param>
/// <param name="Since">Since when the key waits (UTC).</param>
public sealed record PendingApprovalValue( string PartyFullName, string Fingerprint, string Kind, DateTime Since );
