using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;


/// <summary>
/// A Transport is able to send <see cref="IOutgoingMessage"/> and receive <see cref="IncomingMessage"/>.
/// <para>
/// It is instantiated by a <see cref="TransportListener"/> or
/// by <see cref="TransportTypeService.TryConnectAsync(IParallelLogger, TransportTypeAddress, IRemoteKeys, CancellationToken)"/>.
/// </para>
/// </summary>
public abstract partial class Transport
{
    readonly object? _listenerOrTargetAddress;
    // Captures once for all the delegate on the ReadExactlyAsync method.
    readonly Func<Memory<byte>, CancellationToken, ValueTask> _reader;
    readonly string _remoteEndPointDescription;
    readonly IncomingMessageFactory _receiveFactory;
    // StartReceiveAsync sets:
    //  - _receiveHandlers: With the protocol handlers have been resolved from the negotiated ones.
    //  - _receiveCTS: A new CancellationTokenSource created right before calling RunReceiveAsync.
    //                 The Token is provided to _receiveFactory.DoReadAsync for each read.
    PeerProtocolHandler[]? _receiveHandlers;
    CancellationTokenSource? _receiveCTS;

    // Set when this transport has been accepted.
    TransportController? _controller;

    // Ultimate lifetime. 
    // Initiator: Lifetime of this transport is provided by the TransportTypeService.TryConnectToAsync
    //            as soon as the Transport has been created.
    // Listener: Initialized in the constructor.
    [AllowNull]
    CancellationTokenSource _lifeTime;

    // Initiator: This known at the Transport creation time.
    // Listener: This is set by the IncomingConnectionBackTask if the remote party exists.
    IRemoteKeys? _remoteKeys;

    // Set by the TransportController on the TransportManager loop : this is a soft
    // condemned that doesn't signal the LifeTime token.
    GoodbyeMessage? _goodbyeMessage;

    // The ephemeral ECDH key pair of THIS connection, and the session protection derived from it.
    //
    // Both live here and nowhere else, on purpose. A Transport is created per connection and is
    // never pooled (TcpSocketListener and TcpSocketTransportTypeService always construct a new one),
    // so a session key physically cannot outlive its connection. Holding them on the long-lived
    // TransportFeature would reuse the ephemeral across connections — and a reused key under
    // AES-GMAC means a repeated (key, nonce) pair, which leaks the authentication subkey and allows
    // arbitrary forgery. That is a total break, not a degradation.
    //
    // DO NOT make Transport poolable, and do not add session resumption without rekeying.
    ECDiffieHellman? _ephemeral;
    RunPhaseProtection? _protection;
    // Set by StartReceiveAsync: the symmetric moment both peers enter the run phase.
    volatile bool _runPhase;
    readonly object _sendProtectionLock = new object();

    int _disposed;

    /// <summary>
    /// Initializes a new Transport from a <see cref="TransportListener"/>.
    /// </summary>
    /// <param name="listener">The listener that created this transport from an incoming connexion.</param>
    /// <param name="remoteEndPointDescription">
    /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
    /// </param>
    /// <param name="remoteKeys">
    /// When not null, it means that the TransportListener was able to resolve the remote party
    /// among the <see cref="TransportListener.Parties"/>. This is possible for secured connections
    /// when a SSL certificates is available.
    /// </param>
    protected Transport( TransportListener listener,
                         string? remoteEndPointDescription,
                         IRemoteKeys? remoteKeys = null )
        : this( listener._transportManager.SystemClock,
                (object)listener,
                remoteEndPointDescription,
                remoteKeys )
    {
        Throw.CheckNotNullArgument( listener );
    }

    /// <summary>
    /// Initializes a new Transport by an outgoing connection to <paramref name="targetAddress"/>.
    /// We are on a known remote: the local and remote keys are known in this case.
    /// </summary>
    /// <param name="targetAddress">The target address.</param>
    /// <param name="remoteKeys">Remote key manager of this remote party.</param>
    /// <param name="remoteEndPointDescription">
    /// Target address of this Transport. When null <c>"&lt;No EndPoint description&gt;"</c> is used.
    /// </param>
    protected Transport( TransportTypeAddress targetAddress,
                         IRemoteKeys remoteKeys,
                         string? remoteEndPointDescription )
        : this( remoteKeys.Party.ApplicationIdentityService.SystemClock,
                (object)targetAddress,
                remoteEndPointDescription,
                remoteKeys )
    {
        Throw.CheckArgument( remoteKeys != null );
        Throw.CheckNotNullArgument( targetAddress );
    }

    Transport( ISystemClock systemClock,
               object source,
               string? remoteEndPointDescription,
               IRemoteKeys? remoteKeys )
    {
        _remoteEndPointDescription = remoteEndPointDescription ?? "<No EndPoint description>";
        _listenerOrTargetAddress = source;
        _reader = ReadExactlyAsync;
        // Starts with the "0 Protocol" support only.
        // Negotiated protocols are set by StartReceiveAsync.
        _receiveFactory = new IncomingMessageFactory( systemClock );
        _lifeTime = new CancellationTokenSource();
        _remoteKeys = remoteKeys;
    }

    internal void SetCancellationSource( CancellationTokenSource cancellation )
    {
        _lifeTime = cancellation;
    }

    internal void SetController( TransportController controller )
    {
        Throw.DebugAssert( _controller == null && controller != null );
        _controller = controller;
    }

    internal TransportController? Controller => _controller;

    /// <summary>
    /// Gets the protocols that have been negotiated.
    /// </summary>
    public MessageProtocolMap NegotiatedProtocols => _receiveFactory.AllowedProtocols;

    /// <summary>
    /// Gets the listener if this transport is on the listening side.
    /// Null if this transport is the initiator to the non null <see cref="TargetAddress"/>.
    /// </summary>
    public TransportListener? Listener => _listenerOrTargetAddress as TransportListener;

    /// <summary>
    /// Gets the target address if this transport has initiated the connection.
    /// </summary>
    public TransportTypeAddress? TargetAddress => _listenerOrTargetAddress as TransportTypeAddress;

    /// <summary>
    /// Gets a string that describes the remote's endpoint.
    /// </summary>
    public string RemoteEndPointDescription => _remoteEndPointDescription;

    /// <summary>
    /// Gets whether this transport is condemned (or is already dead).
    /// </summary>
    public bool IsCondemned => _goodbyeMessage != null || _lifeTime.IsCancellationRequested;

    /// <summary>
    /// Gets the goodbye message if it has been set.
    /// </summary>
    public GoodbyeMessage? GoodbyeMessage => _goodbyeMessage;

    /// <summary>
    /// Gets the alive token for this transport.
    /// </summary>
    /// <remarks>
    /// This is used as the cancellation token when reading and writing messages.
    /// </remarks>
    public CancellationToken Lifetime => _lifeTime.Token;

    /// <summary>
    /// Gets the last received time.
    /// </summary>
    public DateTime LastReceived => _receiveFactory.LastReceived;

    internal IRemoteKeys? RemoteKeys => _remoteKeys;

    /// <summary>
    /// Gets the run-phase protection once the handshake has derived it, null during the handshake.
    /// </summary>
    internal RunPhaseProtection? Protection => _protection;

    /// <summary>
    /// Gets the MAC algorithm negotiated for this connection, null until the handshake has derived
    /// the session keys.
    /// <para>
    /// Worth surfacing: which primitive a connection ends up using depends on what the two machines
    /// can execute, so on a fleet whose hardware is not known in advance this is the only way to
    /// find out what is actually running.
    /// </para>
    /// </summary>
    public MacAlgorithm? NegotiatedMacAlgorithm => _protection?.Algorithm;

    /// <summary>
    /// Gets a short non-secret identifier of this connection's session keys, null during the
    /// handshake. Both peers compute the same value, so it can be matched across two logs.
    /// </summary>
    public string? SessionId => _protection?.SessionId;

    /// <summary>
    /// Length of a certificate binding: the SHA-256 of a certificate's DER.
    /// </summary>
    public const int CertificateBindingLength = 32;

    /// <summary>
    /// Gets the SHA-256 of the DER of the certificate this side presents on this connection, or an
    /// empty memory when this transport presents none.
    /// <para>
    /// Each side states this inside the signed Zero Protocol transcript, and each checks the peer's
    /// statement against <see cref="RemoteCertificateBinding"/>. Something that terminates the
    /// underlying channel between the two peers has to present a certificate of its own, so what the
    /// peer signed and what actually arrived no longer agree and the handshake fails before any
    /// payload flows. Binding to the certificate rather than to the key it contains is what
    /// <c>SslStream</c> can answer for on both sides.
    /// </para>
    /// <para>
    /// A transport that is not certificate based leaves both of these empty, and the two peers then
    /// agree that nothing is bound — which is also how a peer that believes it is on a secured
    /// transport discovers that it is not.
    /// </para>
    /// </summary>
    public virtual ReadOnlyMemory<byte> LocalCertificateBinding => default;

    /// <summary>
    /// Gets the SHA-256 of the DER of the certificate the peer presented on this connection, or an
    /// empty memory when none was presented. See <see cref="LocalCertificateBinding"/>.
    /// </summary>
    public virtual ReadOnlyMemory<byte> RemoteCertificateBinding => default;

    /// <summary>
    /// Creates this connection's ephemeral key pair and returns its public part for the handshake.
    /// Called exactly once per transport.
    /// </summary>
    internal byte[] CreateEphemeralPublicKey()
    {
        // Normally once per transport, but the protocol-version downgrade retry calls
        // SendInitialMessageAsync a second time on the same transport. The guard used to be a
        // DebugAssert, compiled out in Release, where the previous key was simply overwritten and its
        // native handles abandoned to the finalizer. Dispose the old one instead.
        _ephemeral?.Dispose();
        _ephemeral = RunPhaseProtection.CreateEphemeral();
        return _ephemeral.PublicKey.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Derives this connection's session keys from the peer's ephemeral public key.
    /// </summary>
    /// <returns>False if the peer's key or the selected algorithm is unusable.</returns>
    internal bool DeriveProtection( IParallelLogger logger,
                                    ReadOnlySpan<byte> remoteEphemeralPublicKey,
                                    MacAlgorithm algorithm,
                                    ulong nonce,
                                    ReadOnlySpan<byte> transcript,
                                    bool isInitiator )
    {
        Throw.DebugAssert( "Derived once, after CreateEphemeralPublicKey.", _ephemeral != null && _protection == null );
        try
        {
            _protection = RunPhaseProtection.Derive( _ephemeral, remoteEphemeralPublicKey, algorithm, nonce, transcript, isInitiator );
            logger.Debug( $"Session established with '{_remoteEndPointDescription}': {algorithm}, session {_protection.SessionId}." );
            return true;
        }
        catch( Exception ex )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated,
                          $"Unable to derive the session keys with '{_remoteEndPointDescription}'.", ex );
            return false;
        }
    }

    internal void SetKeys( IRemoteKeys remoteKeys )
    {
        Throw.DebugAssert( _remoteKeys == null );
        _remoteKeys = remoteKeys;
    }

    // The local identity snapshot this connection signs with, from its first signed message to its
    // last: a rotation or a credential renewal in the middle of a handshake must not pair the pieces of
    // two snapshots.
    KeyManagement.LocalIdentityState? _signingState;
    // The peer's operational key and its expiry, learned from its verified identity block. It verifies
    // the signed messages that follow (FinalSuccess, RequiredEnlistUrl, Goodbye), and the connection is
    // closed once the credential expires (DESIGN-key-pre-rotation Q9).
    System.Security.Cryptography.ECDsa? _remoteOperationalKey;
    DateTime _remoteCredentialNotAfter;

    /// <summary>
    /// Gets the local identity snapshot this connection signs with: the first call pins it.
    /// </summary>
    internal KeyManagement.LocalIdentityState GetSigningState( KeyManagement.ILocalKeys keys )
    {
        Interlocked.CompareExchange( ref _signingState, keys.State, null );
        return _signingState!;
    }

    /// <summary>
    /// Gets the peer's operational key, once its identity block has been verified on this connection.
    /// </summary>
    internal System.Security.Cryptography.ECDsa? RemoteOperationalKey => _remoteOperationalKey;

    /// <summary>
    /// Gets the expiry of the peer's operational credential (UTC), default when not known.
    /// </summary>
    internal DateTime RemoteCredentialNotAfter => _remoteCredentialNotAfter;

    /// <summary>
    /// Records the peer's verified operational key. Not disposed with the connection: a SafeHandle
    /// finalizes it, and a message in flight may still be verified with it.
    /// </summary>
    internal void SetRemoteCredential( System.Security.Cryptography.ECDsa key, DateTime notAfter )
    {
        _remoteOperationalKey = key;
        _remoteCredentialNotAfter = notAfter;
    }

    /// <summary>
    /// Called by TransportManager.KillTransport before pushing the transport to be disposed:
    /// this signals the <see cref="Lifetime"/> token and may let some time for the cancellation
    /// to be honored before disposing the transport.
    /// Note that we may have already been SoftCondemned.
    /// </summary>
    /// <returns>False if this transport was already killed.</returns>
    internal bool OnKilled()
    {
        // Why does CTS.Cancel() doesn't return a bool?
        // It has already a CompareExchange!
        if( Interlocked.CompareExchange( ref _disposed, 1, 0 ) == 0 )
        {
            // Signal the cancellation first.
            _lifeTime.Cancel();
            // Then sends the awaker to the send loop: it will see
            // a condemn transport end exits.
            _controller?.OnKilledTransport();
            return true;
        }
        return false;
    }

    /// <summary>
    /// This is thread safe because this can be called from
    /// the TransportManager loop and from the Receive loop when a Goodbye message
    /// from the remote has been received.
    /// </summary>
    internal bool Condemn( GoodbyeMessage m )
    {
        if( Interlocked.CompareExchange( ref _goodbyeMessage, m, null) == null )
        {
            // Stops the receive loop as soon as poosible.
            _receiveCTS?.Cancel();
            return true;
        }
        return false;
    }

    /// <summary>
    /// <see cref="OutgoingMessage.IsValid"/> must be true.
    /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/>
    /// if <see cref="IsCondemned"/> has been set, in such case false is returned.
    /// </summary>
    /// <param name="message">The valid message to send.</param>
    /// <returns>True if the message has been sent, false if <see cref="IsCondemned"/> has been signaled.</returns>
    internal async ValueTask<bool> SendAsync( uint protocolNumber, IOutgoingMessage message )
    {
        Throw.DebugAssert( message != null );
        Throw.DebugAssert( message.IsValid );

        if( _lifeTime.IsCancellationRequested ) return false;

        // The header must stay rented until the send has actually completed: the underlying
        // socket keeps referencing it across every await below. Returning it earlier puts a
        // live buffer back in the shared pool and mis-frames the stream.
        var header = ArrayPool<byte>.Shared.Rent( IOutgoingMessage.MaxWirePrefixLength + RunPhaseProtection.TagLength );
        try
        {
            // Gate on the run-phase flag, NOT on _protection being derived. The listener derives its
            // keys BEFORE it sends AcceptedProtocols, and the initiator before it sends FinalSuccess;
            // both of those are handshake messages that the peer still reads unprotected, because it
            // has not derived yet. The two sides only become symmetric at StartReceiveAsync.
            var protection = _runPhase ? _protection : null;
            if( protection == null )
            {
                // Handshake: these messages carry their own signature instead.
                int len = IOutgoingMessage.WriteWireHeader( protocolNumber, (uint)message.Message.Length, message.IsControl, header );
                return await SendAsync( header.AsMemory( 0, len ), message.Message, _lifeTime.Token ).ConfigureAwait( false );
            }
            // Run phase: the declared length covers payload + tag, and the tag is computed over the
            // header too, so a frame cannot be retargeted at another protocol or silently resized.
            uint wireLength = (uint)message.Message.Length + RunPhaseProtection.TagLength;
            int lenHeader = IOutgoingMessage.WriteWireHeader( protocolNumber, wireLength, message.IsControl, header );
            var tag = header.AsMemory( lenHeader, RunPhaseProtection.TagLength );
            bool signed;
            lock( _sendProtectionLock )
            {
                // Sends are serialized per transport, but the counter must advance exactly once per
                // frame and in the same order the bytes hit the socket.
                signed = protection.SignNext( header.AsSpan( 0, lenHeader ), message.Message, tag.Span );
            }
            // False only when a concurrent teardown disposed the session keys. The transport is
            // already dying: report "not sent" rather than putting an unauthenticated frame out.
            if( !signed ) return false;
            return await SendAsync( header.AsMemory( 0, lenHeader ), message.Message, tag, _lifeTime.Token ).ConfigureAwait( false );
        }
        finally
        {
            ArrayPool<byte>.Shared.Return( header );
        }
    }

    /// <summary>
    /// Root method that calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> with
    /// the <paramref name="messagePrefix"/> and then <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/>
    /// (mono buffer again) or <see cref="SendAsync(ReadOnlySequence{byte}, CancellationToken)"/> (when the message has multiple buffer).
    /// <para>
    /// Calls to this methods are serialized.
    /// </para>
    /// </summary>
    /// <param name="message">The message body.</param>
    /// <param name="messagePrefix">The message prefix.</param>
    /// <returns>False if the <paramref name="cancellation"/> has been signaled, true otherwise.</returns>
    /// <summary>
    /// Run-phase send: header, payload, then the authentication tag.
    /// </summary>
    async ValueTask<bool> SendAsync( ReadOnlyMemory<byte> messagePrefix,
                                     ReadOnlySequence<byte> message,
                                     ReadOnlyMemory<byte> tag,
                                     CancellationToken cancellation )
    {
        try
        {
            await SendAsync( messagePrefix, _lifeTime.Token );
            if( message.IsSingleSegment )
            {
                await SendAsync( message.First, _lifeTime.Token );
            }
            else
            {
                await SendAsync( message, _lifeTime.Token );
            }
            await SendAsync( tag, _lifeTime.Token );
            return true;
        }
        catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
        {
            return false;
        }
    }

    protected virtual async ValueTask<bool> SendAsync( ReadOnlyMemory<byte> messagePrefix, ReadOnlySequence<byte> message, CancellationToken cancellation )
    {
        try
        {
            await SendAsync( messagePrefix, _lifeTime.Token );
            if( message.IsSingleSegment )
            {
                await SendAsync( message.First, _lifeTime.Token );
            }
            else
            {
                await SendAsync( message, _lifeTime.Token );
            }
            return true;
        }
        catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
        {
            return false;
        }
    }

    /// <summary>
    /// Must handle the full <paramref name="buffer"/>.
    /// Calls to this methods are serialized.
    /// </summary>
    /// <param name="buffer">The buffer to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The awaitable.</returns>
    internal protected abstract ValueTask SendAsync( ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken );

    /// <summary>
    /// Sends a <see cref="ReadOnlySequence{T}"/> of bytes.
    /// This throws any error thrown by the underlying transport.
    /// This always returns true except if the operation was canceled and the <paramref name="cancellation"/> token has been signaled.
    /// <para>
    /// <para>
    /// Default implementation simply calls <see cref="SendAsync(ReadOnlyMemory{byte}, CancellationToken)"/> on each segment.
    /// </para>
    /// </para>
    /// <para>
    /// If the underlying transport has a support for multiple buffer sending (like <see cref="System.Net.Sockets.Socket.Send(IList{ArraySegment{byte}})"/>)
    /// this should be overridden to benefits from the performance improvement.
    /// </para>
    /// </summary>
    /// <param name="buffer">The multiple buffers to send.</param>
    /// <param name="cancellation">Cancellation token.</param>
    /// <returns>False if the <paramref name="cancellation"/> has been signaled, true otherwise.</returns>
    protected virtual async ValueTask<bool> SendAsync( ReadOnlySequence<byte> buffer, CancellationToken cancellation )
    {
        try
        {
            foreach( var part in buffer )
            {
                await SendAsync( part, cancellation ).ConfigureAwait( false );
            }
            return true;
        }
        catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
        {
            return false;
        }
    }

    /// <summary>
    /// Must read the incoming available data and return the number of bytes read.
    /// If the underlying transport natively supports exact buffer reading, <see cref="ReadExactlyAsync(Memory{byte}, CancellationToken)"/> should be overridden.
    /// In such case this ReceiveAsync method doesn't need to be supported (it will never be called).
    /// </summary>
    /// <param name="buffer">The buffer to fill with the read data.</param>
    /// <param name="cancellation">Cancellation token.</param>
    /// <returns>The number of bytes actually read.</returns>
    protected abstract ValueTask<int> ReceiveAsync( Memory<byte> buffer, CancellationToken cancellation );

    /// <summary>
    /// Must read exactly the number of bytes of the <paramref name="buffer"/>.
    /// This default implementation loops on <see cref="ReceiveAsync(Memory{byte}, CancellationToken)"/> until the buffer
    /// is filled and throws a <see cref="System.IO.InvalidDataException"/> if ReceiveAsync returns 0 or a negative value.
    /// <para>
    /// If the underlying transport has an efficient support of exact buffer reading this should be overridden and <see cref="ReceiveAsync(Memory{byte}, CancellationToken)"/>
    /// will never be called: this prefixed length transport only use exact buffer reading.
    /// </para>
    /// </summary>
    /// <param name="buffer">The buffer to fill.</param>
    /// <param name="cancellation">Cancellation token.</param>
    /// <returns>The awaitable.</returns>
    protected virtual async ValueTask ReadExactlyAsync( Memory<byte> buffer, CancellationToken cancellation )
    {
        Memory<byte> readBuffer = buffer;
        for(; ; )
        {
            int len = await ReceiveAsync( readBuffer, cancellation ).ConfigureAwait( false );
            if( len <= 0 ) Throw.InvalidDataException( $"End of stream reached on '{ToString()}'." );
            if( len == readBuffer.Length ) return;
            readBuffer = readBuffer.Slice( len );
        }
    }

    internal async ValueTask DestroyAsync( IActivityMonitor monitor )
    {
        _receiveFactory.Dispose();
        // Close the communication handle FIRST: that is what ends the send and receive loops, so
        // the key material is released once nothing is still using it.
        await DisposeAsync( monitor );
        // The session keys and the ephemeral private key die with the connection they belong to.
        // Leaving them to the GC means they outlive it, and each connection leaks a CNG handle until
        // a collection happens to reclaim it.
        //
        // Nulling _protection also makes the release observable (NegotiatedMacAlgorithm and
        // SessionId go null), and means a late frame finds no protection rather than a disposed one.
        // Under _sendProtectionLock: SignNext runs holding it, so disposing outside could zero the
        // key material while a send is midway through computing a tag. With the lock, an in-flight
        // send finishes first, and a send that captured the reference before the exchange finds
        // _disposed set and reports "not sent" - which is the guarantee the comment on SendAsync
        // claims and, until now, did not have.
        lock( _sendProtectionLock )
        {
            var protection = Interlocked.Exchange( ref _protection, null );
            protection?.Dispose();
        }
        var ephemeral = Interlocked.Exchange( ref _ephemeral, null );
        ephemeral?.Dispose();
    }

    /// <summary>
    /// Must close any communication handle.
    /// This is guraranteed to be called once and only once.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <returns>The awaitable.</returns>
    protected abstract ValueTask DisposeAsync( IActivityMonitor monitor );

    /// <summary>
    /// Overridden to return the type name, the <see cref="RemoteEndPointDescription"/> (and <see cref="IsCondemned"/>
    /// if it is true).
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => $"{GetType().Name} - {_remoteEndPointDescription}{(IsCondemned ? " (Condemned)" : "")}";

}
