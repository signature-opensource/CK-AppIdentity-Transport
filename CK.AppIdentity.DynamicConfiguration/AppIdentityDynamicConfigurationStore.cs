using CK.Core;
using CK.Cris.DynamicConfiguration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CK.AppIdentity.DynamicConfiguration;

/// <summary>
/// Keeps the changes of the run properties (CK.Cris.DynamicConfiguration) in the "-Local" store of the App's root party
/// (its <see cref="ILocalParty.LocalFileStore"/>): "DynamicConfiguration.json", written atomically. A local party runs
/// in one process at a time: the file has one writer.
/// </summary>
public sealed class AppIdentityDynamicConfigurationStore : IDynamicConfigurationStore
{
    /// <summary>
    /// The name of the file in the "-Local" store of the root party.
    /// </summary>
    public const string FileName = "DynamicConfiguration.json";

    readonly IApplicationIdentityService _root;

    /// <summary>
    /// Initializes the store.
    /// </summary>
    /// <param name="root">The root party of the App.</param>
    public AppIdentityDynamicConfigurationStore( IApplicationIdentityService root )
    {
        _root = root;
    }

    NormalizedPath FilePath => _root.LocalFileStore.FolderPath.AppendPart( FileName );

    /// <inheritdoc />
    public IReadOnlyDictionary<string, DynamicConfigurationRecord> Load( IActivityMonitor monitor )
    {
        var result = new Dictionary<string, DynamicConfigurationRecord>( StringComparer.OrdinalIgnoreCase );
        var path = FilePath;
        if( !File.Exists( path ) ) return result;
        try
        {
            using var s = _root.LocalFileStore.OpenReadStream( path );
            using var doc = JsonDocument.Parse( s );
            foreach( var p in doc.RootElement.EnumerateObject() )
            {
                result[p.Name] = new DynamicConfigurationRecord( Text( p.Value, "Value" ), Text( p.Value, "ConfiguredValue" ) );
            }
        }
        catch( Exception ex ) when( ex is IOException or JsonException or UnauthorizedAccessException or InvalidOperationException )
        {
            monitor.Error( $"Unable to read '{path}': the recorded changes of the run properties are ignored.", ex );
            result.Clear();
        }
        return result;

        static string? Text( JsonElement e, string name ) => e.TryGetProperty( name, out var v ) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    /// <inheritdoc />
    public void Save( IActivityMonitor monitor, IReadOnlyDictionary<string, DynamicConfigurationRecord> records )
    {
        var path = FilePath;
        _root.LocalFileStore.WriteAtomically( path, s =>
        {
            using var w = new Utf8JsonWriter( s, new JsonWriterOptions { Indented = true } );
            w.WriteStartObject();
            foreach( var (key, r) in records )
            {
                w.WriteStartObject( key );
                if( r.Value == null ) w.WriteNull( "Value" ); else w.WriteString( "Value", r.Value );
                if( r.ConfiguredValue == null ) w.WriteNull( "ConfiguredValue" ); else w.WriteString( "ConfiguredValue", r.ConfiguredValue );
                w.WriteEndObject();
            }
            w.WriteEndObject();
        } );
    }
}
