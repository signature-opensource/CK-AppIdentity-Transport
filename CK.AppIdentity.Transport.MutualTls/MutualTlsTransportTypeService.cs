using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The <c>mtls:</c> transport: the Zero Protocol inside a mutually authenticated TLS channel.
/// <para>
/// A client certificate is always required and always requested — that is what the name says, and
/// server-only TLS is not offered. Both certificates are issued by the presenting party's own
/// identity key (<see cref="LocalIdentityKey.CreateDerivedCertificate"/>), so no private key leaves
/// the package that owns it.
/// </para>
/// <para>
/// Neither side decides anything from the certificate it receives: these chain to nothing either
/// machine trusts, and pinning them would require distributing them. What binds the TLS channel to
/// the identity is that each side states the hash of the certificate it presented inside the signed
/// Zero Protocol transcript, and the other side checks that statement against what arrived. Anything
/// that terminates TLS in between has to present a certificate of its own and cannot make either
/// peer sign a statement about it.
/// </para>
/// <para>
/// Payloads are therefore unreadable on the wire, which is the point of this transport and the
/// reason <c>tcp:</c> exists alongside it rather than being replaced by it.
/// </para>
/// </summary>
public sealed class MutualTlsTransportTypeService : TransportTypeService
{
    /// <summary>
    /// The default port, deliberately not 37120.
    /// <para>
    /// The first bytes on the wire differ — a TLS ClientHello against an InitialMessage — so a peer
    /// pointed at the wrong one produces a parse error rather than a connection. Separate ports make
    /// that immediate instead of puzzling, and let one party listen on both.
    /// </para>
    /// </summary>
    public const int DefaultPort = 37121;

    readonly IPEndPoint _defaultEndPoint;
    readonly TlsCredential _credential;

    public MutualTlsTransportTypeService()
        : base( "mtls" )
    {
        _defaultEndPoint = new IPEndPoint( IPAddress.Any, DefaultPort );
        _credential = new TlsCredential();
    }

    /// <summary>
    /// Gets the credential this application presents, shared by every connection of this type.
    /// </summary>
    internal TlsCredential Credential => _credential;

    /// <summary>
    /// Gets the default listening address on any interface, port <see cref="DefaultPort"/>.
    /// </summary>
    public override object? DefaultListeningAddress => _defaultEndPoint;

    /// <inheritdoc />
    public override TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, ImmutableConfigurationSection section )
    {
        if( IPEndPoint.TryParse( typed, out var endPoint ) )
        {
            if( endPoint.Port == 0 ) endPoint.Port = DefaultPort;
            return new TransportTypeAddress( this, section, endPoint );
        }
        monitor.Error( $"Invalid '{section.Path}' = '{typed}'. It must be an IPAddress with an optional port (defaults to {DefaultPort})." );
        return null;
    }

    /// <inheritdoc />
    protected override async Task<Transport?> TryConnectAsync( IParallelLogger logger,
                                                                        TransportTypeAddress typedAddress,
                                                                        IRemoteKeys remoteKeys,
                                                                        CancellationToken cancellation )
    {
        var ipEndPoint = (IPEndPoint)typedAddress.TypedAddress;
        var socket = new Socket( SocketType.Stream, ProtocolType.Tcp );
        SslStream? ssl = null;
        try
        {
            await socket.ConnectAsync( ipEndPoint, cancellation ).ConfigureAwait( false );
            socket.NoDelay = true;

            var (certificate, localBinding) = _credential.Get( remoteKeys.LocalKeys );

            // Captured in the callback for the same reason the listener does it: the callback runs
            // during the handshake on every stack, whatever the TLS version negotiates.
            X509Certificate2? peerCertificate = null;

            ssl = new SslStream( new NetworkStream( socket, ownsSocket: false ), leaveInnerStreamOpen: false );
            var options = new SslClientAuthenticationOptions
            {
                // The peer is identified by the Zero Protocol, not by this name; it is sent because
                // TLS wants one and it makes a packet capture readable.
                TargetHost = remoteKeys.Party.FullName,
                ClientCertificates = new X509Certificate2Collection( certificate ),
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) =>
                {
                    // Accepted whatever the chain says, and this is not a weakening: the server's
                    // certificate is issued by its own identity and chains to nothing this machine
                    // trusts, so a chain verdict here carries no information. The certificate is
                    // bound to the remote by the statement it must sign about it in the handshake
                    // that follows, and a wrong certificate fails there.
                    peerCertificate = cert as X509Certificate2;
                    return cert != null;
                }
            };
            await ssl.AuthenticateAsClientAsync( options, cancellation ).ConfigureAwait( false );

            if( peerCertificate == null )
            {
                logger.Error( $"The mTLS peer at '{ipEndPoint}' presented no usable certificate." );
                await ssl.DisposeAsync().ConfigureAwait( false );
                socket.Dispose();
                return null;
            }
            return new MutualTlsTransport( typedAddress,
                                           remoteKeys,
                                           ssl,
                                           socket,
                                           localBinding,
                                           TlsCredential.ComputeBinding( peerCertificate ) );
        }
        catch( Exception ex )
        {
            // Including AuthenticationException: a peer that cannot complete the handshake is a
            // connection failure like any other and is retried with the usual back-off.
            logger.Error( $"Unable to establish a mTLS connection to '{ipEndPoint}'.", ex );
            if( ssl != null ) await ssl.DisposeAsync().ConfigureAwait( false );
            socket.Dispose();
            return null;
        }
    }

    /// <inheritdoc />
    protected override TransportListener? TryCreateListener( IActivityMonitor monitor, object opaqueHandle, object typedAddress )
    {
        var ipEndPoint = (IPEndPoint)typedAddress;
        try
        {
            Socket socket = new Socket( SocketType.Stream, ProtocolType.Tcp );
            socket.Bind( ipEndPoint );
            socket.Listen();
            Throw.DebugAssert( socket.LocalEndPoint is IPEndPoint );
            return new MutualTlsListener( this, opaqueHandle, ipEndPoint, socket );
        }
        catch( Exception ex )
        {
            monitor.Error( $"While creating mTLS listener on '{ipEndPoint}'.", ex );
            return null;
        }
    }
}
