using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Testing.Adversarial;

/// <summary>
/// A hostile peer that speaks the Zero Protocol, acting as a <em>listener</em> that a real
/// <see cref="ApplicationIdentityService"/> initiator connects to.
/// <para>
/// It is an independent implementation (see <see cref="PeerWire"/>) so that it can do things the
/// production code would never do: sign with the wrong key, replay a nonce, truncate a frame,
/// oversize a handshake. That is the point — a harness built on the production writer can only
/// produce messages the production writer is willing to produce.
/// </para>
/// <para>
/// Passing a <see cref="PeerCertificate"/> makes it an <c>mtls:</c> peer. Only the transport changes:
/// the framing above it and every message builder are the same, which is what lets the same hostile
/// cases be replayed over TLS — and what lets the harness present one certificate while stating
/// another, the case the whole binding design exists for.
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
    readonly PeerCertificate? _certificate;

    /// <param name="certificate">
    /// When not null, this peer terminates TLS and presents this certificate. It also requests one
    /// from the initiator and accepts whatever arrives, exactly as the real listener does.
    /// </param>
    public AdversarialPeer( PeerCertificate? certificate = null )
    {
        _connections = new List<PeerConnection>();
        _certificate = certificate;
        // Port 0 lets the OS pick a free port: the test reads Address afterwards and feeds it to
        // the remote's configuration, so tests never collide on a fixed port.
        _listener = new TcpListener( IPAddress.Loopback, 0 );
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    /// <summary>The port this peer listens on.</summary>
    public int Port { get; }

    /// <summary>
    /// The address in the form expected by the <c>Parties:N:Address</c> configuration entry, with the
    /// prefix matching what this peer actually speaks.
    /// </summary>
    public string Address => _certificate == null ? $"tcp:127.0.0.1:{Port}" : $"mtls:127.0.0.1:{Port}";

    /// <summary>
    /// Waits for an initiator to connect, completing the TLS handshake when this peer has a
    /// certificate.
    /// </summary>
    public async Task<PeerConnection> AcceptAsync( CancellationToken cancellation = default )
    {
        var client = await _listener.AcceptTcpClientAsync( cancellation );
        PeerConnection c;
        if( _certificate == null )
        {
            c = new PeerConnection( client, client.GetStream(), null, null );
        }
        else
        {
            X509Certificate2? initiatorCertificate = null;
            var ssl = new SslStream( client.GetStream(), leaveInnerStreamOpen: false );
            await ssl.AuthenticateAsServerAsync( new SslServerAuthenticationOptions
            {
                ServerCertificate = _certificate.Certificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = ( s, cert, chain, errors ) =>
                {
                    initiatorCertificate = cert as X509Certificate2;
                    return true;
                }
            }, cancellation );
            c = new PeerConnection( client, ssl, _certificate, initiatorCertificate );
        }
        lock( _connections ) _connections.Add( c );
        return c;
    }

    /// <summary>
    /// The default TCP port a real <see cref="ApplicationIdentityService"/> listens on.
    /// </summary>
    public const int DefaultListenerPort = 37120;

    /// <summary>
    /// The default port a real mutual TLS listener uses.
    /// </summary>
    public const int DefaultMutualTlsPort = 37121;

    /// <summary>
    /// Opens an outbound connection, so the harness can play the hostile INITIATOR against a real
    /// listener. That is the direction exposed to the network, and the one the nonce replay cache
    /// and the clock-offset checks defend.
    /// </summary>
    /// <param name="certificate">
    /// When not null, TLS is negotiated and this certificate is presented as the client certificate.
    /// </param>
    public static async Task<PeerConnection> ConnectAsync( int port = DefaultListenerPort,
                                                           PeerCertificate? certificate = null,
                                                           CancellationToken cancellation = default )
    {
        var client = new TcpClient();
        await client.ConnectAsync( IPAddress.Loopback, port, cancellation );
        if( certificate == null ) return new PeerConnection( client, client.GetStream(), null, null );

        X509Certificate2? listenerCertificate = null;
        var ssl = new SslStream( client.GetStream(), leaveInnerStreamOpen: false );
        await ssl.AuthenticateAsClientAsync( new SslClientAuthenticationOptions
        {
            TargetHost = "adversary",
            ClientCertificates = new X509Certificate2Collection( certificate.Certificate ),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = ( s, cert, chain, errors ) =>
            {
                listenerCertificate = cert as X509Certificate2;
                return true;
            }
        }, cancellation );
        return new PeerConnection( client, ssl, certificate, listenerCertificate );
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
/// One connection between the harness and a real party, cleartext or inside TLS.
/// </summary>
public sealed class PeerConnection : IAsyncDisposable
{
    readonly TcpClient _client;
    readonly Stream _stream;
    readonly PeerCertificate? _presented;
    readonly X509Certificate2? _received;

    internal PeerConnection( TcpClient client, Stream stream, PeerCertificate? presented, X509Certificate2? received )
    {
        _client = client;
        _stream = stream;
        _presented = presented;
        _received = received;
    }

    /// <summary>The stream, for tests that need to do something the helpers do not cover.</summary>
    public Stream Stream => _stream;

    /// <summary>
    /// What this connection states truthfully about the certificate the harness presented, or null on
    /// a cleartext connection. A test that wants to lie about it passes something else to the message
    /// builder — which is the whole reason this is exposed rather than filled in automatically.
    /// </summary>
    public byte[]? TruthfulBinding => _presented?.Binding;

    /// <summary>
    /// The certificate the real party presented, or null on a cleartext connection.
    /// </summary>
    public X509Certificate2? ReceivedCertificate => _received;

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
