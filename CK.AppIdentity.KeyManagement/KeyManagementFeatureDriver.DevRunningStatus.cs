using CK.Core;
using System;
using System.Linq;
using System.Text.Json;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// Contributes the "KeyManagement" section of the running status of a development party (the "DevRunningStatus" feature
/// of CK.AppIdentity): the key checkpoint of each local party (see <see cref="ILocalKeys.Checkpoint"/>), what another
/// party configures as its trust anchor ("Local:TrustAnchors:{FullName}"). It is rewritten after each key event.
/// </summary>
public partial class KeyManagementFeatureDriver : IDevRunningStatusContributor
{
    void IDevRunningStatusContributor.Activate( IActivityMonitor monitor, Action onChanged )
    {
        _keyEventAppended.PerfectEvent.Sync += ( m, k ) => onChanged();
    }

    // The key management doesn't make a party not ready.
    bool IDevRunningStatusContributor.IsReady => true;

    void IDevRunningStatusContributor.Write( Utf8JsonWriter writer )
    {
        var s = ApplicationIdentityService;
        writer.WriteStartObject( "KeyManagement" );
        writer.WriteStartArray( "Checkpoints" );
        foreach( var local in s.TenantDomains.Cast<ILocalParty>().Prepend( s ) )
        {
            if( local.GetFeature<LocalKeys>() is not { } keys ) continue;
            writer.WriteStartObject();
            writer.WriteString( "FullName", local.FullName.Path );
            writer.WriteString( "Checkpoint", keys.Checkpoint.ToString() );
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}
