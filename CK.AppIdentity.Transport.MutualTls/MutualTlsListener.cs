using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Net;
using System.Net.Security;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Accepts TLS connections, requiring a client certificate.
/// <para>
/// Unlike a cleartext listener, accepting here is not free: a TLS handshake is a round trip plus a
/// signature verification. So the accept loop does not perform it — a client that connects and then
/// says nothing would otherwise stall every subsequent accept until it timed out, which is a denial
/// of service that costs the attacker one socket.
/// </para>
/// </summary>
sealed class MutualTlsListener : TransportListener
{
    readonly MutualTlsTransportTypeService _service;
    readonly IPEndPoint _address;
    readonly Socket _listenSocket;
    readonly CancellationTokenSource _listenCTS;

    public MutualTlsListener( MutualTlsTransportTypeService service, object opaqueHandle, IPEndPoint address, Socket listenSocket )
        : base( opaqueHandle, service )
    {
        _service = service;
        _address = address;
        _listenSocket = listenSocket;
        _listenCTS = new CancellationTokenSource();
        _ = Task.Run( RunAcceptAsync );
    }

    public IPEndPoint Address => _address;

    public IPEndPoint ActualListeningAddress => (IPEndPoint)_listenSocket.LocalEndPoint!;

    public override string EndPointDescription
    {
        get
        {
            var a = _address;
            var r = ActualListeningAddress;
            return a.Equals( r ) ? $"mTLS on {a}" : $"mTLS on {a} -> {r}";
        }
    }

    protected override bool IsListeningAddress( object address )
    {
        var ipEndPoint = (IPEndPoint)address;
        return ipEndPoint.Equals( Address ) || ipEndPoint.Equals( ActualListeningAddress );
    }

    protected override ValueTask DisposeAsync( IActivityMonitor monitor )
    {
        _listenCTS.Cancel();
        return default;
    }

    async Task RunAcceptAsync()
    {
        Logger.Info( $"Starting '{ToString()}'." );
        while( true )
        {
            try
            {
                var acceptSocket = await _listenSocket.AcceptAsync( _listenCTS.Token );
                acceptSocket.NoDelay = true;
                // The address without the port: with it, every connection would be its own source and
                // the per-source limit would never bind.
                var sourceKey = (acceptSocket.RemoteEndPoint as IPEndPoint)?.Address.ToString();
                // Reserved HERE rather than at OnIncomingTransport, because the handshake is the
                // expensive part and it happens first. Taking the slot afterwards would cap only what
                // comes after the cost, which is the opposite of what a cap is for.
                if( !TryReserveIncomingSlot( sourceKey ) )
                {
                    acceptSocket.Dispose();
                    continue;
                }
                var acceptedAtUtc = DateTime.UtcNow;
                // Off the accept loop: the handshake takes a round trip and must not hold the queue.
                _ = Task.Run( () => HandshakeAsync( acceptSocket, sourceKey, acceptedAtUtc ) );
            }
            catch( OperationCanceledException ) when( _listenCTS.IsCancellationRequested )
            {
                break;
            }
            catch( SocketException e ) when( e.SocketErrorCode == SocketError.OperationAborted )
            {
                break;
            }
            catch( SocketException ex )
            {
                Logger.Warn( $"An incoming mTLS connection got reset while it was in the backlog on '{_address}'.", ex );
            }
            catch( Exception ex )
            {
                Logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Unexpected error in mTLS listener on '{_address}'.", ex );
            }
        }
        Logger.Info( $"Ending '{ToString()}' (disposing Listening socket)." );
        try
        {
            _listenSocket.Dispose();
        }
        catch( Exception ex )
        {
            Logger.Error( "While disposing mTLS listener.", ex );
        }
    }

    /// <summary>
    /// Works out which of this listener's parties presented <paramref name="peerCertificate"/>, by
    /// checking whose pinned identity signed it.
    /// <para>
    /// The identity issues the TLS credential, so the certificate's own key says nothing about who
    /// this is — what identifies it is the signature on it. That signature is checked against the
    /// bare pinned key (<see cref="IdentityIssuance"/>), which is what lets this work without the
    /// identity certificate ever being distributed.
    /// </para>
    /// <para>
    /// Returning null is normal and is not a rejection. A peer this listener has never trusted — the
    /// first contact of a party that is about to be adopted — resolves to nothing and continues
    /// exactly as it would on a cleartext connection, which is what keeps one code path for the trust
    /// decision. Deciding trust here instead would close the door on every new party.
    /// </para>
    /// <para>
    /// What the answer is worth: it is a lookup, and the incoming path holds it against the signed
    /// InitialMessage before anything is built on it. A peer that makes this resolve to somebody else
    /// has to hold that somebody's identity private key, and is then caught claiming a different name
    /// in a message it signed itself.
    /// </para>
    /// </summary>
    IRemoteKeys? TryResolveRemote( X509Certificate2 peerCertificate )
    {
        var authority = IdentityIssuance.TryGetAuthorityKeyIdentifier( peerCertificate );
        if( authority == null ) return null;
        // Parties is an immutable array swapped on change, so this needs no synchronization.
        foreach( var party in Parties )
        {
            var trusted = party.RemoteKeys.TrustedIdentity;
            if( trusted == null ) continue;
            // The identifier narrows to one candidate for free; the signature is what decides.
            if( !authority.Equals( IdentityIssuance.GetKeyIdentifier( trusted ), StringComparison.Ordinal ) ) continue;
            if( IdentityIssuance.WasIssuedBy( peerCertificate, trusted ) )
            {
                // Worth a line: it is the only place the transport says who it thinks this is, before
                // the peer has said anything, and it is what the InitialMessage is then held against.
                Logger.Info( $"Incoming mTLS connection identified as '{party.Party.FullName}' from its certificate." );
                return party.RemoteKeys;
            }
        }
        return null;
    }

    /// <summary>
    /// Completes the TLS handshake and hands the connection over, or closes it.
    /// <para>
    /// The slot taken by the accept loop is released on every path that does not reach
    /// <see cref="TransportListener.OnIncomingTransport"/>: leaking one would tighten the cap
    /// permanently, so a handshake that fails often would end up refusing everything.
    /// </para>
    /// </summary>
    async Task HandshakeAsync( Socket socket, string? sourceKey, DateTime acceptedAtUtc )
    {
        SslStream? ssl = null;
        bool handedOver = false;
        try
        {
            var (certificate, localBinding) = _service.Credential.Get( LocalKeys );

            // Captured in the callback rather than read from SslStream.RemoteCertificate afterwards.
            // The callback runs during the handshake on every stack; when the server sees the client
            // certificate is TLS-version and platform dependent, and has been known not to be before
            // the first read completes. Same amount of code, none of the question.
            X509Certificate2? peerCertificate = null;

            ssl = new SslStream( new NetworkStream( socket, ownsSocket: false ), leaveInnerStreamOpen: false );
            var options = new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                // Nothing issues these certificates but the peers themselves, so there is no
                // revocation list to consult and asking for one is a stall waiting to happen.
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) =>
                {
                    // Every well-formed client certificate is accepted, deliberately. Who this is
                    // cannot be decided here: the answer arrives in the InitialMessage, signed, and
                    // the certificate is bound to that answer by the statement each side makes about
                    // it inside the signed transcript. Refusing here on chain errors would reject
                    // every peer, since these certificates chain to nothing this machine trusts.
                    peerCertificate = cert as X509Certificate2;
                    return cert != null;
                }
            };

            // One budget for the whole of an unauthenticated connection's life. The remainder is
            // carried into the Zero Protocol phase through acceptedAtUtc, so a peer that spends
            // most of it here does not get a fresh allowance afterwards.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource( _listenCTS.Token );
            cts.CancelAfter( IncomingNegotiationTimeout );
            await ssl.AuthenticateAsServerAsync( options, cts.Token ).ConfigureAwait( false );

            if( peerCertificate == null )
            {
                Logger.Warn( $"Incoming mTLS connection from '{sourceKey}' presented no usable client certificate." );
                return;
            }
            var transport = new MutualTlsTransport( this,
                                                    ssl,
                                                    socket,
                                                    localBinding,
                                                    TlsCredential.ComputeBinding( peerCertificate ),
                                                    TryResolveRemote( peerCertificate ) );
            // Cannot return false: the slot is already ours.
            OnIncomingTransport( transport, sourceKey, slotReserved: true, acceptedAtUtc );
            handedOver = true;
        }
        catch( OperationCanceledException )
        {
            Logger.Warn( $"TLS handshake timed out for an incoming connection from '{sourceKey}'." );
        }
        catch( Exception ex ) when( ex is AuthenticationException or IOException or SocketException )
        {
            // A peer that cannot complete a TLS handshake is an ordinary event on a listening port:
            // a scanner, a plain tcp: client on the wrong port, a peer whose clock makes its own
            // certificate invalid. One line, no stack.
            Logger.Warn( $"TLS handshake failed for an incoming connection from '{sourceKey}': {ex.GetType().Name}." );
        }
        catch( Exception ex )
        {
            Logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                          $"Unexpected error while handshaking an incoming mTLS connection from '{sourceKey}'.", ex );
        }
        finally
        {
            if( !handedOver )
            {
                ReleaseIncomingSlot( sourceKey );
                if( ssl != null ) await ssl.DisposeAsync().ConfigureAwait( false );
                socket.Dispose();
            }
        }
    }
}
