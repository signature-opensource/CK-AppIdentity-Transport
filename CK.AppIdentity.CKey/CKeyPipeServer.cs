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

    // The delay before the loop tries again after a failed accept or a failed creation of an instance.
    static readonly TimeSpan _retryDelay = TimeSpan.FromSeconds( 1 );

    readonly ApplicationIdentityService _app;
    readonly CKeyOperations _operations;
    readonly string _pipeName;
    // At most MaxInstances - 1 requests are handled at once: with the listening instance, the pipe never needs more.
    readonly SemaphoreSlim _handlers = new SemaphoreSlim( MaxInstances - 1, MaxInstances - 1 );
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
        catch( Exception )
        {
            // The loop logs its errors: the teardown never throws.
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

    // A failed accept (a client that connects and leaves) or a failed creation of an instance is logged and the loop goes
    // on (after a short delay): CKey stays available for the life of the process.
    async Task LoopAsync( NamedPipeServerStream first, CancellationToken cancel )
    {
        var monitor = new ActivityMonitor( $"The \"CKey\" pipe '{_pipeName}' of '{_app.FullName}'." );
        NamedPipeServerStream? listening = first;
        try
        {
            while( !cancel.IsCancellationRequested )
            {
                NamedPipeServerStream? connected = null;
                try
                {
                    listening ??= Create( _pipeName, firstInstance: false );
                    await listening.WaitForConnectionAsync( cancel ).ConfigureAwait( false );
                    connected = listening;
                    listening = null;
                    // The connected instance holds the name while the loop waits for a free handler.
                    await _handlers.WaitAsync( cancel ).ConfigureAwait( false );
                    // The next instance listens before the request is handled: the name is never free.
                    try
                    {
                        listening = Create( _pipeName, firstInstance: false );
                    }
                    finally
                    {
                        var handled = connected;
                        connected = null;
                        _ = Task.Run( () => HandleAsync( handled, cancel ) );
                    }
                }
                catch( OperationCanceledException ) when( cancel.IsCancellationRequested )
                {
                    connected?.Dispose();
                    break;
                }
                catch( Exception ex )
                {
                    connected?.Dispose();
                    listening?.Dispose();
                    listening = null;
                    monitor.Warn( $"The \"CKey\" pipe '{_pipeName}' failed to accept a request: it listens again.", ex );
                    try
                    {
                        await Task.Delay( _retryDelay, cancel ).ConfigureAwait( false );
                    }
                    catch( OperationCanceledException )
                    {
                        break;
                    }
                }
            }
        }
        finally
        {
            listening?.Dispose();
            monitor.MonitorEnd();
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
            _handlers.Release();
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
