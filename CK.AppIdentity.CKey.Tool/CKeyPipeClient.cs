using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.CKey.Tool;

/// <summary>
/// The client side of the CKey pipes: a running party that allows the "CKey" feature listens on one pipe per process,
/// named <see cref="Prefix"/> followed by a hash of the full name of its application. A request is one connection: a
/// UTF-8 JSON message prefixed by its length (4 bytes, little-endian), answered the same way.
/// </summary>
public static class CKeyPipeClient
{
    /// <summary>
    /// The prefix of the name of the pipes.
    /// </summary>
    public const string Prefix = "CKey_";

    /// <summary>
    /// The maximal length of a message.
    /// </summary>
    public const int MaxMessageLength = 1024 * 1024;

    /// <summary>
    /// A running party found by <see cref="DiscoverAsync"/>: its pipe and the answer of its "names" operation.
    /// </summary>
    /// <param name="PipeName">The name of the pipe.</param>
    /// <param name="Application">The full name of the application.</param>
    /// <param name="Tenants">The full names of its tenant domains.</param>
    /// <param name="Folder">The folder of the running host.</param>
    /// <param name="ProcessId">The process identifier.</param>
    public sealed record Process( string PipeName, string Application, IReadOnlyList<string> Tenants, string Folder, int ProcessId )
    {
        /// <summary>
        /// Gets whether this process hosts a local party.
        /// </summary>
        /// <param name="fullName">The full name of the local party.</param>
        /// <returns>True when it is the application or one of its tenant domains.</returns>
        public bool Hosts( string fullName ) => Application == fullName || Tenants.Contains( fullName );
    }

    /// <summary>
    /// Gets the names of the CKey pipes of the machine (the ones the current OS user can reach are answered).
    /// </summary>
    /// <returns>The pipe names.</returns>
    public static IReadOnlyList<string> GetPipeNames()
    {
        try
        {
            if( OperatingSystem.IsWindows() )
            {
                return Directory.GetFiles( @"\\.\pipe\" )
                                .Select( p => p.Substring( @"\\.\pipe\".Length ) )
                                .Where( n => n.StartsWith( Prefix, StringComparison.Ordinal ) )
                                .Distinct()
                                .ToList();
            }
            // Elsewhere, a .NET named pipe is a Unix domain socket "CoreFxPipe_{name}" in the temporary folder.
            return Directory.GetFiles( Path.GetTempPath(), "CoreFxPipe_" + Prefix + "*" )
                            .Select( p => Path.GetFileName( p ).Substring( "CoreFxPipe_".Length ) )
                            .ToList();
        }
        catch( IOException )
        {
            return [];
        }
    }

    /// <summary>
    /// Finds the running parties of the current OS user: asks each CKey pipe its names.
    /// </summary>
    /// <param name="cancel">The cancellation token.</param>
    /// <returns>The processes that answered.</returns>
    public static async Task<IReadOnlyList<Process>> DiscoverAsync( CancellationToken cancel = default )
    {
        var result = new List<Process>();
        foreach( var pipe in GetPipeNames() )
        {
            try
            {
                using var answer = await SendAsync( pipe, w => w.WriteString( "op", "names" ), TimeSpan.FromSeconds( 2 ), cancel ).ConfigureAwait( false );
                var r = answer.RootElement;
                if( !r.TryGetProperty( "ok", out var ok ) || !ok.GetBoolean() ) continue;
                result.Add( new Process( pipe,
                                         r.GetProperty( "application" ).GetString()!,
                                         r.GetProperty( "tenants" ).EnumerateArray().Select( t => t.GetString()! ).ToList(),
                                         r.GetProperty( "folder" ).GetString()!,
                                         r.GetProperty( "pid" ).GetInt32() ) );
            }
            catch( Exception ex ) when( ex is IOException or TimeoutException or UnauthorizedAccessException or JsonException or InvalidOperationException or KeyNotFoundException )
            {
                // Not one of ours, another OS user's, or gone: ignored.
            }
        }
        return result;
    }

    /// <summary>
    /// Sends a request to a pipe and reads its answer.
    /// </summary>
    /// <param name="pipeName">The name of the pipe.</param>
    /// <param name="request">Writes the properties of the request (the object is opened and closed here).</param>
    /// <param name="timeout">The maximal time to connect.</param>
    /// <param name="cancel">The cancellation token.</param>
    /// <returns>The answer.</returns>
    public static async Task<JsonDocument> SendAsync( string pipeName, Action<Utf8JsonWriter> request, TimeSpan timeout, CancellationToken cancel = default )
    {
        // CurrentUserOnly: the server must run as the current user (a pipe created by another user is refused).
        using var client = new NamedPipeClientStream( ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly );
        await client.ConnectAsync( timeout, cancel ).ConfigureAwait( false );
        var m = new MemoryStream();
        using( var w = new Utf8JsonWriter( m ) )
        {
            w.WriteStartObject();
            request( w );
            w.WriteNumber( "clientPid", Environment.ProcessId );
            w.WriteString( "clientUser", Environment.UserName );
            w.WriteEndObject();
        }
        await WriteMessageAsync( client, m.ToArray(), cancel ).ConfigureAwait( false );
        var answer = await ReadMessageAsync( client, cancel ).ConfigureAwait( false );
        return JsonDocument.Parse( answer );
    }

    /// <summary>
    /// Writes a message: its length (4 bytes, little-endian), then its bytes.
    /// </summary>
    /// <param name="s">The stream.</param>
    /// <param name="message">The message.</param>
    /// <param name="cancel">The cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public static async Task WriteMessageAsync( Stream s, ReadOnlyMemory<byte> message, CancellationToken cancel )
    {
        var length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian( length, message.Length );
        await s.WriteAsync( length, cancel ).ConfigureAwait( false );
        await s.WriteAsync( message, cancel ).ConfigureAwait( false );
        await s.FlushAsync( cancel ).ConfigureAwait( false );
    }

    /// <summary>
    /// Reads a message written by <see cref="WriteMessageAsync"/>.
    /// </summary>
    /// <param name="s">The stream.</param>
    /// <param name="cancel">The cancellation token.</param>
    /// <returns>The message.</returns>
    public static async Task<byte[]> ReadMessageAsync( Stream s, CancellationToken cancel )
    {
        var length = new byte[4];
        await s.ReadExactlyAsync( length, cancel ).ConfigureAwait( false );
        int len = BinaryPrimitives.ReadInt32LittleEndian( length );
        if( len < 0 || len > MaxMessageLength ) throw new InvalidDataException( $"Invalid message length: {len}." );
        var message = new byte[len];
        await s.ReadExactlyAsync( message, cancel ).ConfigureAwait( false );
        return message;
    }
}
