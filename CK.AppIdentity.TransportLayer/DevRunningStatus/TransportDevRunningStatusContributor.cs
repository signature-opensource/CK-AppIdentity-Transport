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
public sealed class TransportDevRunningStatusContributor : IDevRunningStatusContributor
{
    readonly ApplicationIdentityService _s;

    /// <summary>
    /// Initializes a new <see cref="TransportDevRunningStatusContributor"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    public TransportDevRunningStatusContributor( ApplicationIdentityService s )
    {
        _s = s;
    }

    /// <inheritdoc />
    public void Activate( IActivityMonitor monitor, Action onChanged )
    {
        // The transport feature may be disallowed.
        var transport = _s.GetFeature<TransportManagerFeature>();
        if( transport != null )
        {
            transport.ConnectionAvailabilityChanged.Sync += ( m, t ) => onChanged();
            transport.TransportChanged.Sync += ( m, t ) => onChanged();
        }
    }

    /// <inheritdoc />
    public bool IsReady => GetTransports().All( t => t.TargetAddress == null || t.ConnectionAvailability == ConnectionAvailability.Connected );

    /// <inheritdoc />
    public void Write( Utf8JsonWriter writer )
    {
        var transports = GetTransports().ToList();
        writer.WriteStartObject( "Transport" );
        writer.WriteStartArray( "Listeners" );
        foreach( var l in GetListeners( transports ) )
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

    IEnumerable<TransportFeature> GetTransports() => _s.AllRemotes.Select( r => r.GetFeature<TransportFeature>() ).Where( t => t != null )!;

    // The listeners of the remotes, and the "AlwaysListening" ones of the local parties.
    IEnumerable<TransportListener> GetListeners( List<TransportFeature> transports )
    {
        var alwaysListening = _s.TenantDomains.Cast<ILocalParty>()
                                              .Prepend( _s )
                                              .SelectMany( l => l.GetFeature<TransportListener[]>() ?? [] );
        return transports.SelectMany( t => t.Listeners ?? [] )
                         .Concat( alwaysListening )
                         .Distinct();
    }
}
