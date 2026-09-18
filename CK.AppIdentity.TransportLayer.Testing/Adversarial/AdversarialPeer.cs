using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// A hostile peer that speaks the Zero Protocol over a raw TCP socket, acting as a
/// <em>listener</em> that a real <see cref="ApplicationIdentityService"/> initiator connects to.
/// <para>
/// It is an independent implementation (see <see cref="PeerWire"/>) so that it can do things the
/// production code would never do: sign with the wrong key, replay a nonce, truncate a frame,
/// oversize a handshake. That is the point — a harness built on the production writer can only
/// produce messages the production writer is willing to produce.
/// </para>
/// <para>
/// Usage: construct (it binds immediately so <see cref="Address"/> is available for the remote's
/// configuration), then <c>await</c> <see cref="AcceptAsync"/> and drive the connection.
/// </para>
/// </summary>
public sealed class AdversarialPeer : IAsyncDisposable
{
    readonly TcpListener _listener;
    readonly List<PeerConnection> _connections;

    public AdversarialPeer()
    {
        _connections = new List<PeerConnection>();
        // Port 0 lets the OS pick a free port: the test reads Address afterwards and feeds it to
        // the remote's configuration, so tests never collide on a fixed port.
        _listener = new TcpListener( IPAddress.Loopback, 0 );
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    /// <summary>The port this peer listens on.</summary>
    public int Port { get; }

    /// <summary>
    /// The address in the form expected by the <c>Parties:N:Address</c> configuration entry.
    /// </summary>
    public string Address => $"tcp:127.0.0.1:{Port}";

    /// <summary>
    /// Waits for an initiator to connect.
    /// </summary>
    public async Task<PeerConnection> AcceptAsync( CancellationToken cancellation = default )
    {
        var client = await _listener.AcceptTcpClientAsync( cancellation );
        var c = new PeerConnection( client );
        lock( _connections ) _connections.Add( c );
        return c;
    }

    /// <summary>
    /// The default TCP port a real <see cref="ApplicationIdentityService"/> listens on.
    /// </summary>
    public const int DefaultListenerPort = 37120;

    /// <summary>
    /// Opens an outbound connection, so the harness can play the hostile INITIATOR against a real
    /// listener. That is the direction exposed to the network, and the one the nonce replay cache
    /// and the clock-offset checks defend.
    /// </summary>
    public static async Task<PeerConnection> ConnectAsync( int port = DefaultListenerPort,
                                                           CancellationToken cancellation = default )
    {
        var client = new TcpClient();
        await client.ConnectAsync( IPAddress.Loopback, port, cancellation );
        return new PeerConnection( client );
    }

    public async ValueTask DisposeAsync()
    {
        _listener.Stop();
        PeerConnection[] all;
        lock( _connections )
        {
            all = _connections.ToArray();
            _connections.Clear();
        }
        foreach( var c in all ) await c.DisposeAsync();
        _listener.Dispose();
    }
}

/// <summary>
/// One accepted connection from a real initiator.
/// </summary>
public sealed class PeerConnection : IAsyncDisposable
{
    readonly TcpClient _client;
    readonly NetworkStream _stream;

    internal PeerConnection( TcpClient client )
    {
        _client = client;
        _stream = client.GetStream();
    }

    /// <summary>The raw stream, for tests that need to do something the helpers do not cover.</summary>
    public NetworkStream Stream => _stream;

    /// <summary>
    /// Reads the next frame.
    /// </summary>
    public Task<PeerWire.Frame2> ReadFrameAsync( CancellationToken cancellation = default )
        => PeerWire.ReadFrameAsync( _stream, cancellation );

    /// <summary>
    /// Reads the next frame and parses it as an <c>InitialMessage</c>.
    /// </summary>
    public async Task<PeerInitialMessage> ReadInitialMessageAsync( CancellationToken cancellation = default )
    {
        var frame = await ReadFrameAsync( cancellation );
        if( !frame.IsZeroProtocol )
        {
            throw new InvalidOperationException( $"Expected a '0 Protocol' frame, got protocol number {frame.ProtocolNumber}." );
        }
        return PeerInitialMessage.Parse( frame.Payload );
    }

    /// <summary>
    /// Sends a "0 Protocol" frame carrying <paramref name="payload"/>.
    /// </summary>
    public Task SendZeroFrameAsync( ReadOnlyMemory<byte> payload, CancellationToken cancellation = default )
    {
        var frame = PeerWire.Frame( payload.Span, PeerWire.ZeroProtocolNumber );
        return _stream.WriteAsync( frame, cancellation ).AsTask();
    }

    /// <summary>
    /// Sends raw bytes with no framing at all — for truncation and malformed-input tests.
    /// </summary>
    public Task SendRawAsync( ReadOnlyMemory<byte> bytes, CancellationToken cancellation = default )
        => _stream.WriteAsync( bytes, cancellation ).AsTask();

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _stream.DisposeAsync();
        }
        catch( Exception )
        {
            // The peer may already be gone; this is a test helper tearing down.
        }
        _client.Dispose();
    }
}
