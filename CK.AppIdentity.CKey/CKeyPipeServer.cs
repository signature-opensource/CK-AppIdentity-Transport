using CK.Core;
using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.CKey;

/// <summary>
/// The pipe of the "CKey" feature: one per process (<see cref="GetPipeName"/>), reachable by the OS user that runs the
/// party only. On Windows, its security grants the current user and denies the network clients (a Windows named pipe can
/// be reached from another machine); elsewhere it is a Unix domain socket restricted to the current user
/// (<see cref="PipeOptions.CurrentUserOnly"/>). One request per connection (see <see cref="CKeyOperations"/>).
/// </summary>
public sealed class CKeyPipeServer
{
    /// <summary>
    /// The prefix of the name of the pipes: the ckey tool finds the running parties by it.
    /// </summary>
    public const string Prefix = "CKey_";

    /// <summary>
    /// The maximal length of a message (its length is written on 4 bytes, little-endian, before it).
    /// </summary>
    public const int MaxMessageLength = 1024 * 1024;

    const int MaxInstances = 4;

    readonly ApplicationIdentityService _app;
    readonly CKeyOperations _operations;
    readonly string _pipeName;
    CancellationTokenSource? _cts;
    Task? _loop;

    internal CKeyPipeServer( ApplicationIdentityService app )
    {
        _app = app;
        _operations = new CKeyOperations( app );
        _pipeName = GetPipeName( app.FullName.Path );
    }

    /// <summary>
    /// Gets the name of the pipe of an application: <see cref="Prefix"/> followed by the 16 first hexadecimal digits of
    /// the SHA-256 of its full name (a full name contains '/' and can be long).
    /// </summary>
    /// <param name="applicationFullName">The full name of the application.</param>
    /// <returns>The name of the pipe.</returns>
    public static string GetPipeName( string applicationFullName )
    {
        return Prefix + Convert.ToHexStringLower( SHA256.HashData( Encoding.UTF8.GetBytes( applicationFullName ) ) ).Substring( 0, 16 );
    }

    /// <summary>
    /// Gets the name of the pipe.
    /// </summary>
    public string PipeName => _pipeName;

    internal void Start( IActivityMonitor monitor )
    {
        NamedPipeServerStream first;
        try
        {
            first = Create( _pipeName, firstInstance: true );
        }
        catch( Exception ex ) when( ex is IOException or UnauthorizedAccessException )
        {
            // Another process already listens on this name: the same application started twice, or a squatter (the
            // clients check that the server runs as their OS user).
            monitor.Error( $"The \"CKey\" pipe '{_pipeName}' of '{_app.FullName}' can't be created: CKey is not available in this process.", ex );
            return;
        }
        _cts = new CancellationTokenSource();
        _loop = Task.Run( () => LoopAsync( first, _cts.Token ) );
        monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"The \"CKey\" pipe '{_pipeName}' of '{_app.FullName}' is listening (OS user '{Environment.UserName}')." );
    }

    internal async Task StopAsync()
    {
        if( _cts == null ) return;
        _cts.Cancel();
        try
        {
            await _loop!.ConfigureAwait( false );
        }
        catch( OperationCanceledException )
        {
        }
        _cts.Dispose();
        _cts = null;
    }

    /// <summary>
    /// Creates an instance of the pipe.
    /// </summary>
    /// <param name="pipeName">The name of the pipe.</param>
    /// <param name="firstInstance">Whether this must be the first instance of the name (no other process listens on it).</param>
    /// <returns>The server stream.</returns>
    internal static NamedPipeServerStream Create( string pipeName, bool firstInstance )
    {
        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        if( OperatingSystem.IsWindows() )
        {
            return NamedPipeServerStreamAcl.Create( pipeName,
                                                    PipeDirection.InOut,
                                                    MaxInstances,
                                                    PipeTransmissionMode.Byte,
                                                    options,
                                                    0,
                                                    0,
                                                    CreateWindowsSecurity() );
        }
        return new NamedPipeServerStream( pipeName, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte, options | PipeOptions.CurrentUserOnly );
    }

    /// <summary>
    /// The security of the pipe on Windows: the current user only (its owner, full control), the network clients denied.
    /// </summary>
    /// <returns>The security.</returns>
    [System.Runtime.Versioning.SupportedOSPlatform( "windows" )]
    internal static PipeSecurity CreateWindowsSecurity()
    {
        var user = WindowsIdentity.GetCurrent().User!;
        var security = new PipeSecurity();
        security.SetOwner( user );
        security.AddAccessRule( new PipeAccessRule( user, PipeAccessRights.FullControl, AccessControlType.Allow ) );
        security.AddAccessRule( new PipeAccessRule( new SecurityIdentifier( WellKnownSidType.NetworkSid, null ), PipeAccessRights.FullControl, AccessControlType.Deny ) );
        return security;
    }

    async Task LoopAsync( NamedPipeServerStream listening, CancellationToken cancel )
    {
        try
        {
            while( !cancel.IsCancellationRequested )
            {
                await listening.WaitForConnectionAsync( cancel ).ConfigureAwait( false );
                var connected = listening;
                // The next instance listens before the request is handled: the name is never free.
                listening = Create( _pipeName, firstInstance: false );
                _ = Task.Run( () => HandleAsync( connected, cancel ), cancel );
            }
        }
        finally
        {
            listening.Dispose();
        }
    }

    async Task HandleAsync( NamedPipeServerStream pipe, CancellationToken cancel )
    {
        var monitor = new ActivityMonitor( $"CKey request on '{_app.FullName}'." );
        try
        {
            using( pipe )
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource( cancel );
                timeout.CancelAfter( TimeSpan.FromSeconds( 30 ) );
                var request = await ReadMessageAsync( pipe, timeout.Token ).ConfigureAwait( false );
                // Only the OS user of this process can connect (the security of the pipe).
                var answer = _operations.Handle( monitor, request, Environment.UserName );
                await WriteMessageAsync( pipe, answer, timeout.Token ).ConfigureAwait( false );
            }
        }
        catch( Exception ex ) when( ex is not OperationCanceledException || !cancel.IsCancellationRequested )
        {
            monitor.Warn( "While handling a CKey request.", ex );
        }
        finally
        {
            monitor.MonitorEnd();
        }
    }

    static async Task<byte[]> ReadMessageAsync( Stream s, CancellationToken cancel )
    {
        var length = new byte[4];
        await s.ReadExactlyAsync( length, cancel ).ConfigureAwait( false );
        int len = BinaryPrimitives.ReadInt32LittleEndian( length );
        if( len < 0 || len > MaxMessageLength ) throw new InvalidDataException( $"Invalid CKey message length: {len}." );
        var message = new byte[len];
        await s.ReadExactlyAsync( message, cancel ).ConfigureAwait( false );
        return message;
    }

    static async Task WriteMessageAsync( Stream s, byte[] message, CancellationToken cancel )
    {
        var length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian( length, message.Length );
        await s.WriteAsync( length, cancel ).ConfigureAwait( false );
        await s.WriteAsync( message, cancel ).ConfigureAwait( false );
        await s.FlushAsync( cancel ).ConfigureAwait( false );
    }
}
