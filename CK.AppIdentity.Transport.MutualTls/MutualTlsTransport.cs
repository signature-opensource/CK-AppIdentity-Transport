using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// A <see cref="Transport"/> whose frames travel inside an authenticated <see cref="SslStream"/>.
/// <para>
/// The TLS layer proves possession of a private key; it does not say whose. What makes the two one
/// lock is that each side states, inside the signed Zero Protocol transcript, the certificate it
/// presented, and the other side checks that statement against what actually arrived — which is what
/// <see cref="LocalCertificateBinding"/> and <see cref="RemoteCertificateBinding"/> feed.
/// </para>
/// <para>
/// The per-frame MAC of the run phase is kept over this transport too, although TLS already provides
/// integrity: it is bound to the AppIdentity session rather than to the channel, so it keeps meaning
/// something if the channel is ever terminated somewhere in between.
/// </para>
/// </summary>
sealed class MutualTlsTransport : Transport
{
    readonly SslStream _ssl;
    readonly Socket _socket;
    readonly ReadOnlyMemory<byte> _localBinding;
    readonly ReadOnlyMemory<byte> _remoteBinding;

    /// <summary>Incoming: accepted by a listener, the peer not yet identified.</summary>
    public MutualTlsTransport( MutualTlsListener listener,
                               SslStream ssl,
                               Socket socket,
                               ReadOnlyMemory<byte> localBinding,
                               ReadOnlyMemory<byte> remoteBinding )
        : base( listener, socket.RemoteEndPoint?.ToString() )
    {
        _ssl = ssl;
        _socket = socket;
        _localBinding = localBinding;
        _remoteBinding = remoteBinding;
    }

    /// <summary>Outgoing: we know which remote we dialled before connecting.</summary>
    public MutualTlsTransport( TransportTypeAddress targetAddress,
                               IRemoteKeys remoteKeys,
                               SslStream ssl,
                               Socket socket,
                               ReadOnlyMemory<byte> localBinding,
                               ReadOnlyMemory<byte> remoteBinding )
        : base( targetAddress, remoteKeys, socket.RemoteEndPoint?.ToString() ?? targetAddress.TypedAddress.ToString() )
    {
        _ssl = ssl;
        _socket = socket;
        _localBinding = localBinding;
        _remoteBinding = remoteBinding;
    }

    /// <inheritdoc />
    public override ReadOnlyMemory<byte> LocalCertificateBinding => _localBinding;

    /// <inheritdoc />
    public override ReadOnlyMemory<byte> RemoteCertificateBinding => _remoteBinding;

    protected override async ValueTask DisposeAsync( IActivityMonitor monitor )
    {
        // The SslStream owns the network stream and closes the socket with it; the socket is disposed
        // as well because a half-open one is worse than a redundant call.
        try
        {
            await _ssl.DisposeAsync().ConfigureAwait( false );
        }
        catch( Exception ex )
        {
            monitor.Debug( $"While disposing the SslStream of '{RemoteEndPointDescription}'.", ex );
        }
        _socket.Dispose();
    }

    protected override ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellation = default )
    {
        return _ssl.ReadAsync( buffer, cancellation );
    }

    // No loop here, unlike a raw socket: Stream.WriteAsync writes the whole buffer or throws.
    protected override ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellation = default )
    {
        return _ssl.WriteAsync( buffer, cancellation );
    }
}
