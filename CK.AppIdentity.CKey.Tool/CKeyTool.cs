using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace CK.AppIdentity.CKey.Tool;

/// <summary>
/// The commands of the ckey tool. The party is the one that runs from the folder of the tool (the copy next to its host)
/// unless "--party" names one (a full name: an application or one of its tenant domains).
/// </summary>
public static class CKeyTool
{
    /// <summary>
    /// The usage text.
    /// </summary>
    public const string Usage = """
        ckey: the local user interface of the AppIdentity store of a running party ("CKey" feature).

          ckey list
              The running parties of this OS user: their processes, applications and tenant domains.
          ckey status [--party <full name>]
              The checkpoint of the party (for a "TrustAnchors" of another party) and its peering issues.
          ckey approve <remote> <code> [--party <full name>]
              Approves the key that a remote presented with the approval code shown on the remote.
          ckey export trust [<file>] [--party <full name>] [--expires <duration>] [--pwd <password>]
              Exports the trust of the party (its key event log) to a file encrypted by a password (generated and
              printed, unless --pwd gives it). The duration: 30m, 2h, 1d... (1h by default, 7d at most).
          ckey import trust <file> [--party <full name>] [--pwd <password>]
              Pins the remote whose trust the file holds (the password is asked, unless --pwd gives it).

        Without --party, the party is the one that runs from the folder of this ckey.
        """;

    /// <summary>
    /// Runs a command.
    /// </summary>
    /// <param name="args">The arguments.</param>
    /// <param name="output">The output.</param>
    /// <param name="error">The error output.</param>
    /// <param name="readPassword">Reads a password interactively (null when it can't).</param>
    /// <param name="toolFolder">The folder of the tool: its party is the one that runs from there.</param>
    /// <returns>The exit code: 0 on success, 1 on error, 2 on a usage error.</returns>
    public static async Task<int> RunAsync( string[] args, TextWriter output, TextWriter error, Func<string, string?> readPassword, string toolFolder )
    {
        var positional = new List<string>();
        var options = new Dictionary<string, string>();
        for( int i = 0; i < args.Length; ++i )
        {
            var a = args[i];
            if( a is "--party" or "--expires" or "--pwd" )
            {
                if( i + 1 >= args.Length ) return UsageError( error, $"The option '{a}' needs a value." );
                options[a] = args[++i];
            }
            else if( a.StartsWith( "--", StringComparison.Ordinal ) )
            {
                return UsageError( error, $"Unknown option '{a}'." );
            }
            else
            {
                positional.Add( a );
            }
        }
        options.TryGetValue( "--party", out var party );
        try
        {
            switch( positional.FirstOrDefault() )
            {
                case "list" when positional.Count == 1:
                    return await ListAsync( output );
                case "status" when positional.Count == 1:
                    return await StatusAsync( output, error, party, toolFolder );
                case "approve" when positional.Count == 3:
                    return await ApproveAsync( output, error, party, toolFolder, positional[1], positional[2] );
                case "export" when positional.Count is 2 or 3 && positional[1] == "trust":
                    {
                        var expires = TrustFile.DefaultLifetime;
                        if( options.TryGetValue( "--expires", out var e ) && !TrustFile.TryParseDuration( e, out expires ) )
                        {
                            return UsageError( error, $"Invalid duration '{e}': 30m, 2h, 1d... (7d at most)." );
                        }
                        options.TryGetValue( "--pwd", out var pwd );
                        return await ExportAsync( output, error, party, toolFolder, positional.Count == 3 ? positional[2] : null, expires, pwd );
                    }
                case "import" when positional.Count == 3 && positional[1] == "trust":
                    {
                        if( !options.TryGetValue( "--pwd", out var pwd ) )
                        {
                            pwd = readPassword( "Password: " );
                            if( pwd == null ) return UsageError( error, "No interactive console: give the password with --pwd." );
                        }
                        return await ImportAsync( output, error, party, toolFolder, positional[2], pwd );
                    }
                default:
                    output.WriteLine( Usage );
                    return positional.Count == 0 || positional[0] is "help" or "-h" or "-?" ? 0 : 2;
            }
        }
        catch( Exception ex ) when( ex is IOException or TimeoutException or UnauthorizedAccessException or JsonException or InvalidDataException )
        {
            error.WriteLine( $"Error: {ex.Message}" );
            return 1;
        }
    }

    static int UsageError( TextWriter error, string message )
    {
        error.WriteLine( message );
        error.WriteLine( "See 'ckey help'." );
        return 2;
    }

    static async Task<int> ListAsync( TextWriter output )
    {
        var processes = await CKeyPipeClient.DiscoverAsync();
        if( processes.Count == 0 )
        {
            output.WriteLine( "No running party of this OS user allows the \"CKey\" feature." );
            return 0;
        }
        foreach( var p in processes )
        {
            output.WriteLine( $"Process #{p.ProcessId} ({p.Folder})" );
            output.WriteLine( $"  Application: {p.Application}" );
            foreach( var t in p.Tenants ) output.WriteLine( $"  Tenant:      {t}" );
        }
        return 0;
    }

    // The process and the full name of the local party: the one named by --party, otherwise the application that runs
    // from the folder of the tool.
    static async Task<(CKeyPipeClient.Process? Process, string Party)> ResolveAsync( TextWriter error, string? party, string toolFolder )
    {
        var processes = await CKeyPipeClient.DiscoverAsync();
        if( party != null )
        {
            var hosts = processes.Where( p => p.Hosts( party ) ).ToList();
            if( hosts.Count == 1 ) return (hosts[0], party);
            error.WriteLine( hosts.Count == 0
                                ? $"No running party '{party}' of this OS user allows the \"CKey\" feature (see 'ckey list')."
                                : $"'{party}' runs in {hosts.Count} processes: stop the extra ones." );
            return (null, party);
        }
        var own = processes.Where( p => SameFolder( p.Folder, toolFolder ) ).ToList();
        if( own.Count == 1 ) return (own[0], own[0].Application);
        error.WriteLine( own.Count == 0
                            ? "No party runs from the folder of this ckey: name it with --party <full name> (see 'ckey list')."
                            : $"{own.Count} parties run from the folder of this ckey: name one with --party <full name> (see 'ckey list')." );
        return (null, "");
    }

    static bool SameFolder( string a, string b )
    {
        static string Normalize( string p ) => Path.GetFullPath( p ).TrimEnd( Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar );
        return string.Equals( Normalize( a ), Normalize( b ), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal );
    }

    static async Task<JsonDocument?> RequestAsync( TextWriter error, CKeyPipeClient.Process process, Action<Utf8JsonWriter> request )
    {
        var answer = await CKeyPipeClient.SendAsync( process.PipeName, request, TimeSpan.FromSeconds( 5 ) );
        var r = answer.RootElement;
        if( r.TryGetProperty( "ok", out var ok ) && ok.GetBoolean() ) return answer;
        error.WriteLine( r.TryGetProperty( "error", out var e ) ? e.GetString() : "The party refused the request." );
        answer.Dispose();
        return null;
    }

    static async Task<int> StatusAsync( TextWriter output, TextWriter error, string? party, string toolFolder )
    {
        var (process, fullName) = await ResolveAsync( error, party, toolFolder );
        if( process == null ) return 1;
        using var answer = await RequestAsync( error, process, w =>
        {
            w.WriteString( "op", "status" );
            w.WriteString( "party", fullName );
        } );
        if( answer == null ) return 1;
        var r = answer.RootElement;
        output.WriteLine( $"Party:      {fullName} (process #{process.ProcessId})" );
        output.WriteLine( $"Checkpoint: {r.GetProperty( "checkpoint" ).GetString()}" );
        var issues = r.GetProperty( "issues" );
        if( issues.GetArrayLength() == 0 )
        {
            output.WriteLine( "No peering issue." );
        }
        foreach( var i in issues.EnumerateArray() )
        {
            output.WriteLine( $"- {i.GetProperty( "remote" ).GetString()}: {i.GetProperty( "kind" ).GetString()}" );
            if( i.TryGetProperty( "code", out var code ) && code.ValueKind == JsonValueKind.String ) output.WriteLine( $"    Approval code:   {code.GetString()}" );
            if( i.TryGetProperty( "fingerprint", out var f ) && f.ValueKind == JsonValueKind.String ) output.WriteLine( $"    Key fingerprint: {f.GetString()}" );
            if( i.TryGetProperty( "enlistUrl", out var u ) && u.ValueKind == JsonValueKind.String )
            {
                output.WriteLine( $"    Enlistment URL:  {u.GetString()} ({(i.GetProperty( "enlistUrlAuthenticated" ).GetBoolean() ? "authenticated" : "NOT authenticated: check it out of band")})" );
            }
        }
        return 0;
    }

    static async Task<int> ApproveAsync( TextWriter output, TextWriter error, string? party, string toolFolder, string remote, string code )
    {
        var (process, fullName) = await ResolveAsync( error, party, toolFolder );
        if( process == null ) return 1;
        using var answer = await RequestAsync( error, process, w =>
        {
            w.WriteString( "op", "approve" );
            w.WriteString( "party", fullName );
            w.WriteString( "remote", remote );
            w.WriteString( "code", code );
        } );
        if( answer == null ) return 1;
        output.WriteLine( $"'{fullName}' approved the key of '{remote}'." );
        return 0;
    }

    static async Task<int> ExportAsync( TextWriter output, TextWriter error, string? party, string toolFolder, string? file, TimeSpan lifetime, string? pwd )
    {
        var (process, fullName) = await ResolveAsync( error, party, toolFolder );
        if( process == null ) return 1;
        using var answer = await RequestAsync( error, process, w =>
        {
            w.WriteString( "op", "export" );
            w.WriteString( "party", fullName );
        } );
        if( answer == null ) return 1;
        var r = answer.RootElement;
        var events = r.GetProperty( "events" ).EnumerateArray().Select( e => e.GetBytesFromBase64() ).ToList();
        var expires = DateTime.UtcNow + lifetime;
        var password = pwd ?? TrustFile.GeneratePassword();
        file ??= string.Concat( fullName.Select( c => char.IsLetterOrDigit( c ) ? c : '_' ) ) + ".ckeytrust";
        await File.WriteAllBytesAsync( file, TrustFile.Encrypt( new TrustFile.Content( fullName, events, expires ), password ) );
        output.WriteLine( $"The trust of '{fullName}' is exported to '{Path.GetFullPath( file )}', until {expires:u}." );
        if( pwd == null )
        {
            output.WriteLine( $"Password: {password}" );
            output.WriteLine( "Give the password by another channel than the file." );
        }
        return 0;
    }

    static async Task<int> ImportAsync( TextWriter output, TextWriter error, string? party, string toolFolder, string file, string password )
    {
        if( !TrustFile.TryDecrypt( await File.ReadAllBytesAsync( file ), password, DateTime.UtcNow, out var content, out var reason ) )
        {
            error.WriteLine( reason );
            return 1;
        }
        var (process, fullName) = await ResolveAsync( error, party, toolFolder );
        if( process == null ) return 1;
        using var answer = await RequestAsync( error, process, w =>
        {
            w.WriteString( "op", "import" );
            w.WriteString( "party", fullName );
            w.WriteString( "fullName", content!.FullName );
            w.WriteStartArray( "events" );
            foreach( var e in content.Events ) w.WriteBase64StringValue( e );
            w.WriteEndArray();
        } );
        if( answer == null ) return 1;
        output.WriteLine( $"'{fullName}' trusts '{content!.FullName}' (#{answer.RootElement.GetProperty( "seq" ).GetInt32()})." );
        return 0;
    }
}
