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
/// </list>
/// The party is ready when every outgoing remote (with a <see cref="TransportFeature.TargetAddress"/>) is
/// <see cref="ConnectionAvailability.Connected"/>.
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
        }
    }

    bool IDevRunningStatusContributor.IsReady => GetRunningStatusTransports().All( t => t.TargetAddress == null || t.ConnectionAvailability == ConnectionAvailability.Connected );

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
