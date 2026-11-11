using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace CK.AppIdentity.CKey;

/// <summary>
/// The operations of the CKey pipe. A request is a JSON object: its "op", its arguments, and the "clientPid" and
/// "clientUser" stated by the tool. The answer is a JSON object: "ok" true with the result, or "ok" false and "error".
/// Every operation is logged <see cref="ActivityMonitor.Tags.SecurityCritical"/>.
/// <list type="bullet">
///   <item>"names": the full names of the application and its tenant domains, the folder of the host and the process.</item>
///   <item>"status" (party): the checkpoint of the local party and its peering issues.</item>
///   <item>"approve" (party, remote, code): <see cref="PeeringIssue.TryApprove(IActivityMonitor, string)"/>.</item>
///   <item>"export" (party): the last events of its key event log (public data).</item>
///   <item>"import" (party, fullName, events): pins a configured remote of the local party from its events.</item>
/// </list>
/// </summary>
sealed class CKeyOperations
{
    readonly ApplicationIdentityService _app;

    public CKeyOperations( ApplicationIdentityService app ) => _app = app;

    public byte[] Handle( IActivityMonitor monitor, byte[] request, string osUser )
    {
        var m = new MemoryStream();
        using var w = new Utf8JsonWriter( m );
        w.WriteStartObject();
        try
        {
            using var d = JsonDocument.Parse( request );
            var r = d.RootElement;
            var op = r.GetProperty( "op" ).GetString();
            var client = $"OS user '{osUser}', process #{(r.TryGetProperty( "clientPid", out var pid ) ? pid.GetInt32() : 0)} (stated)";
            string? error = op switch
            {
                "names" => Names( w ),
                "status" => Status( monitor, w, r, client ),
                "approve" => Approve( monitor, w, r, client ),
                "export" => Export( monitor, w, r, client ),
                "import" => Import( monitor, w, r, client ),
                _ => $"Unknown operation '{op}'."
            };
            if( error != null )
            {
                monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"CKey '{op}' refused for {client}: {error}" );
                w.WriteBoolean( "ok", false );
                w.WriteString( "error", error );
            }
            else
            {
                w.WriteBoolean( "ok", true );
            }
        }
        catch( Exception ex ) when( ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException )
        {
            monitor.Warn( ActivityMonitor.Tags.SecurityCritical, "Invalid CKey request.", ex );
            w.WriteBoolean( "ok", false );
            w.WriteString( "error", "Invalid request." );
        }
        w.WriteEndObject();
        w.Flush();
        return m.ToArray();
    }

    string? Names( Utf8JsonWriter w )
    {
        w.WriteString( "application", _app.FullName.Path );
        w.WriteStartArray( "tenants" );
        foreach( var t in _app.TenantDomains ) w.WriteStringValue( t.FullName.Path );
        w.WriteEndArray();
        w.WriteString( "folder", AppContext.BaseDirectory );
        w.WriteNumber( "pid", Environment.ProcessId );
        return null;
    }

    ILocalParty? FindLocal( JsonElement r )
    {
        var name = r.GetProperty( "party" ).GetString();
        return _app.FullName.Path == name
                ? _app
                : _app.TenantDomains.FirstOrDefault( t => t.FullName.Path == name );
    }

    string? Status( IActivityMonitor monitor, Utf8JsonWriter w, JsonElement r, string client )
    {
        var local = FindLocal( r );
        if( local == null ) return "No such local party in this process.";
        var keys = local.GetFeature<ILocalKeys>();
        if( keys == null ) return $"'{local.FullName}' has no \"KeyManagement\" feature.";
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"CKey status of '{local.FullName}' for {client}." );
        w.WriteString( "checkpoint", keys.Checkpoint.ToString() );
        w.WriteStartArray( "issues" );
        foreach( var i in GetIssues( local ) )
        {
            w.WriteStartObject();
            w.WriteString( "remote", i.FullName );
            w.WriteString( "kind", i.Kind.ToString() );
            w.WriteString( "code", i.ApprovalCode );
            w.WriteString( "fingerprint", i.RemoteKeyFingerprintForApproval );
            w.WriteString( "enlistUrl", i.EnlistUrl );
            w.WriteBoolean( "enlistUrlAuthenticated", i.IsEnlistUrlAuthenticated );
            w.WriteEndObject();
        }
        w.WriteEndArray();
        return null;
    }

    // The peering issues of a local party: its remotes', and the unknown callers that claim its domain.
    IEnumerable<PeeringIssue> GetIssues( ILocalParty local )
    {
        var transport = _app.GetFeature<TransportManagerFeature>();
        if( transport == null ) return [];
        return transport.GetPeeringIssues().Where( i => i.Remote != null ? i.Remote.Party.Owner == local : local == _app );
    }

    string? Approve( IActivityMonitor monitor, Utf8JsonWriter w, JsonElement r, string client )
    {
        var local = FindLocal( r );
        if( local == null ) return "No such local party in this process.";
        var remote = r.GetProperty( "remote" ).GetString();
        var code = r.GetProperty( "code" ).GetString() ?? "";
        var issue = GetIssues( local ).FirstOrDefault( i => i.FullName == remote && i.CanAcceptRemoteIdentity );
        if( issue == null ) return $"'{local.FullName}' has no pending approval of '{remote}'.";
        if( !issue.TryApprove( monitor, code, null, out var notReady ) )
        {
            return notReady
                    ? $"The approval code with '{remote}' is not known yet: retry in a few seconds."
                    : $"The code doesn't match the one of '{remote}'.";
        }
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"CKey: '{local.FullName}' approved the key of '{remote}' with its code, for {client}." );
        return null;
    }

    string? Export( IActivityMonitor monitor, Utf8JsonWriter w, JsonElement r, string client )
    {
        var local = FindLocal( r );
        if( local == null ) return "No such local party in this process.";
        var keys = local.GetFeature<ILocalKeys>();
        if( keys == null ) return $"'{local.FullName}' has no \"KeyManagement\" feature.";
        var state = keys.State;
        var events = state.GetEventsFrom( Math.Max( 0, state.Head.Seq - KeyEventChain.MaxEventWindow + 1 ) );
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"CKey: the trust of '{local.FullName}' ({keys.Checkpoint}) is exported for {client}." );
        w.WriteStartArray( "events" );
        foreach( var e in events ) w.WriteBase64StringValue( e.Encoded.Span );
        w.WriteEndArray();
        return null;
    }

    string? Import( IActivityMonitor monitor, Utf8JsonWriter w, JsonElement r, string client )
    {
        var local = FindLocal( r );
        if( local == null ) return "No such local party in this process.";
        var fullName = r.GetProperty( "fullName" ).GetString();
        var remote = local.Remotes.FirstOrDefault( p => p.FullName.Path == fullName );
        if( remote == null ) return $"'{fullName}' is not a remote of '{local.FullName}'.";
        if( remote.GetFeature<IRemoteKeys>() is not { } keys ) return $"The remote '{fullName}' has no \"KeyManagement\" feature.";
        if( keys.IsAnchored ) return $"The remote '{fullName}' is anchored: its trust anchor is the authority (update it rather than importing a trust).";
        var events = new List<KeyEvent>();
        try
        {
            foreach( var e in r.GetProperty( "events" ).EnumerateArray() ) events.Add( KeyEvent.Read( e.GetBytesFromBase64() ) );
        }
        catch( InvalidDataException )
        {
            return "The events of the trust are invalid.";
        }
        var check = KeyEventChain.Verify( fullName!, events, null );
        if( check.Verdict != KeyChainVerdict.Unpinned )
        {
            return $"The key event log of '{fullName}' doesn't verify ({check.Verdict}).";
        }
        var head = check.Head!;
        if( !keys.SetTrustedIdentity( monitor, head ) && !IsPinned( keys, fullName!, head ) )
        {
            return $"The identity of '{fullName}' can't be pinned (revoked, or refused: see the log of '{local.FullName}').";
        }
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"CKey: '{local.FullName}' pinned '{fullName}' (#{head.Seq}) from an imported trust, for {client}." );
        w.WriteNumber( "seq", head.Seq );
        return null;
    }

    static bool IsPinned( IRemoteKeys keys, string fullName, KeyEvent head )
        => keys.TrustedEvent is { } pinned
           && pinned.Seq == head.Seq
           && pinned.GetDigest( fullName ).Span.SequenceEqual( head.GetDigest( fullName ).Span );
}
