using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

/// <summary>
/// The "#Dev" trust anchors: the checkpoint is read from the running status that the anchored party writes in its shared
/// folder of the dev store.
/// </summary>
static class DevAnchors
{
    /// <summary>
    /// Gets the shared folder of a party in the store of an application: "{StoreRoot}/{#Environment}/{the full name
    /// without the environment}". This is how CK.AppIdentity computes it for a remote (the shared folder of a party that
    /// is not a remote of the application can't be obtained from it).
    /// </summary>
    internal static NormalizedPath GetSharedFolder( ILocalParty local, string fullName )
    {
        var n = new NormalizedPath( fullName );
        var env = n.LastPart;
        var p = n.Path;
        return local.ApplicationIdentityService.Configuration.StoreRootPath.Combine( $"{env}/{p.AsSpan( 0, p.Length - env.Length - 1 )}" );
    }

    /// <summary>
    /// Reads the checkpoint of a party from its running status, in its shared folder. Null when it can't be read (the
    /// party has not started yet).
    /// </summary>
    internal static KeyCheckpoint? Read( IActivityLineEmitter logger, string fullName, NormalizedPath sharedFolder )
    {
        var bytes = StoreFileReader.TryReadAllBytes( sharedFolder.AppendPart( DevRunningStatusFeatureDriver.FileName ) );
        if( bytes == null ) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse( bytes );
            if( doc.RootElement.TryGetProperty( "KeyManagement", out var km ) && km.TryGetProperty( "Checkpoints", out var cs ) )
            {
                foreach( var c in cs.EnumerateArray() )
                {
                    if( c.GetProperty( "FullName" ).GetString() == fullName
                        && KeyCheckpoint.TryParse( c.GetProperty( "Checkpoint" ).GetString(), out var checkpoint, out _ ) )
                    {
                        logger.Info( $"The trust anchor of '{fullName}' is read from its running status in the dev store: {checkpoint}." );
                        return checkpoint;
                    }
                }
            }
        }
        catch( Exception ex ) when( ex is System.Text.Json.JsonException or InvalidOperationException or KeyNotFoundException )
        {
            logger.Warn( $"Unable to read the running status of '{fullName}' in the dev store: {ex.Message}" );
        }
        return null;
    }
}
