using CK.Core;
using System.Buffers;
using System.Buffers.Binary;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Factory for <see cref="IncomingMessage"/>.
/// There is only 1 way to create an incoming message: reading it from an asynchronous buffer provider
/// that reads an exact count of bytes.
/// <para>
/// This class is thread safe.
/// </para>
/// </summary>
public sealed class IncomingMessageFactory : IDisposable
{
    MessageProtocolMap _protocols;
    DateTime _lastReceived;
    MutableSequence<byte>? _cachedOneBuffer;
    readonly ISystemClock _systemClock;
    // Null during the handshake (those messages are signed instead) and set once the transport
    // enters the run phase.
    RunPhaseProtection? _protection;

    /// <summary>
    /// We work with an initial and first buffer of 4K. This is enough for small messages and
    /// since we control the slicing, we ensure that we fill it when the message is bigger.
    /// </summary>
    public const int FirstSegmentLength = 4096;

    /// <summary>
    /// Constructor for "0 Protocol".
    /// Internally, a factory starts in this mode and is "upgraded" once the protocols
    /// have been negotiated and the Transport takes control of this factory (Bound mode).
    /// </summary>
    internal IncomingMessageFactory( ISystemClock systemClock )
    {
        _protocols = new MessageProtocolMap();
        _systemClock = systemClock;
    }

    /// <summary>
    /// Called by Transport.StartReceiveAsync: the protocols have been negociated.
    /// </summary>
    /// <param name="protocols">The negociated protocols.</param>
    internal void SetAllowedProtocols( MessageProtocolMap protocols )
    {
        Throw.DebugAssert( protocols.IsValid );
        _protocols = protocols;
    }

    /// <summary>
    /// Called by Transport.StartReceiveAsync: from now on every frame carries an authentication tag
    /// and is rejected unless it verifies, in order, against the session key.
    /// </summary>
    internal void SetRunPhaseProtection( RunPhaseProtection protection )
    {
        Throw.DebugAssert( protection != null && _protection == null );
        _protection = protection;
    }

    /// <summary>
    /// Verifies a fully read frame and returns it with its tag hidden, or null when the frame is
    /// not authentic or arrived out of order.
    /// </summary>
    IncomingMessage? VerifyAndCreate( MessageProtocol protocol, MutableSequence<byte> buffer, int prefixLength )
    {
        Throw.DebugAssert( _protection != null );
        const int tagLength = RunPhaseProtection.TagLength;
        var wire = buffer.GetReadOnlySequence();
        long payloadLength = wire.Length - prefixLength - tagLength;
        if( payloadLength < 0 ) return null;

        Span<byte> header = stackalloc byte[IOutgoingMessage.MaxWirePrefixLength];
        wire.Slice( 0, prefixLength ).CopyTo( header );
        Span<byte> tag = stackalloc byte[tagLength];
        wire.Slice( wire.Length - tagLength ).CopyTo( tag );

        return _protection.VerifyNext( header.Slice( 0, prefixLength ), wire.Slice( prefixLength, payloadLength ), tag )
                ? new IncomingMessage( this, protocol, buffer, prefixLength, tagLength )
                : null;
    }

    /// <summary>
    /// Initializes a new <see cref="IncomingMessageFactory"/> that handles a set of
    /// protocols: the <see cref="MessageProtocol.ZeroProtocol"/> is always
    /// handled.
    /// <para>
    /// This is currently only used by unit tests.
    /// </para>
    /// </summary>
    /// <param name="protocols">
    /// A map that must be <see cref="MessageProtocolMap.IsValid"/> and negotiated
    /// with the other party.
    /// </param>
    public IncomingMessageFactory( MessageProtocolMap protocols )
    {
        Throw.CheckArgument( protocols.IsValid );
        _protocols = protocols;
        _systemClock = SystemClock.Default;
    }

    /// <summary>
    /// Gets the protocols map that this factory is allowed to handle.
    /// </summary>
    public MessageProtocolMap AllowedProtocols => _protocols;

    /// <summary>
    /// Gets the last received time.
    /// </summary>
    public DateTime LastReceived => _lastReceived;

    /// <summary>
    /// Creates a <see cref="IncomingMessage"/> from an asynchronous buffer provider.
    /// This throws any exception thrown by the underlying transport except the <see cref="OperationCanceledException"/> if
    /// <paramref name="cancellation"/> token has been signaled, in such case <see cref="IncomingMessage.Canceled"/> is returned.
    /// When <see cref="IncomingMessage.Invalid"/> is returned it means that an invalid length prefix has been read or it exceeds
    /// the <paramref name="maxMessageLength"/> parameter. 
    /// <para>
    /// This is only used by unit tests.
    /// </para>
    /// </summary>
    /// <param name="exactReader">The reader to use.</param>
    /// <param name="maxMessageLength">Optional maximal message length. Defaults to <see cref="int.MaxValue"/> (2 GiB).</param>
    /// <param name="cancellation">Cancellation token.</param>
    /// <returns>
    /// A message that may be one of the special messages <see cref="IncomingMessage.Invalid"/>, <see cref="IncomingMessage.Canceled"/>,
    /// <see cref="IncomingMessage.Empty"/> or <see cref="IncomingMessage.EmptyAck"/>.
    /// </returns>
    public Task<IncomingMessage> ReadAsync( Func<Memory<byte>, CancellationToken, ValueTask> exactReader,
                                            int maxMessageLength = int.MaxValue,
                                            CancellationToken cancellation = default )
    {
        Throw.CheckNotNullArgument( exactReader );
        Throw.CheckOutOfRangeArgument( maxMessageLength > 0 );
        return DoReadAsync( exactReader, maxMessageLength, cancellation );
    }

    internal async Task<IncomingMessage> DoReadAsync( Func<Memory<byte>, CancellationToken, ValueTask> exactReader,
                                                      int maxMessageLength,
                                                      CancellationToken cancellation )
    {
        bool releaseBuffer = true;
        var buffer = GetBuffer();
        try
        {
            var header = buffer.GetMemory( FirstSegmentLength );
            Throw.DebugAssert( buffer.Length == 0 );
            // We first read exactly 2 bytes. 
            await exactReader( header.Slice( 0, 2 ), cancellation ).ConfigureAwait( false );
            byte firstByte = header.Span[0];
            uint protocolNumber = (byte)(firstByte & 0b00000111);
            // If the protocol is not allowed, this is a serious error.
            MessageProtocol? protocol = null;
            if( protocolNumber == 0 ) protocol = MessageProtocol.ZeroProtocol;
            else if( !_protocols.IsValid || protocolNumber > _protocols.Protocols.Count )
            {
                Throw.InvalidDataException( $"Unsupported protocol number '{protocolNumber}' received." );
            }
            else
            {
                protocol = _protocols.Protocols[(int)protocolNumber - 1];
            }
            _lastReceived = _systemClock.UtcNow;
            // The declared length is chosen by the peer, so it is bounded by what THIS protocol
            // accepts before a single byte of payload is read. Both length checks below happen
            // before any allocation for the message, so this is the whole of the defence: without
            // it a 5-byte header could ask for a 2 GiB buffer — and with frames authenticated, that
            // allocation would happen before the MAC could reject it.
            Throw.DebugAssert( protocol != null );
            int maxLength = Math.Min( maxMessageLength, protocol.MaxIncomingMessageLength );
            // In the run phase the declared length covers payload + tag (see Transport.SendAsync), so
            // comparing it against maxLength unchanged would put the effective PAYLOAD ceiling 16
            // bytes below the one that applies during the handshake - and it would move silently at
            // the phase boundary. A channel legitimately sending exactly MaxIncomingMessageLength
            // would have the frame refused as Invalid, which kills the transport; the message has
            // already been consumed, so it is lost and the link bounces. No hostile peer needed.
            // The cap belongs to the payload; the tag is protocol overhead and is accounted here.
            if( _protection != null && maxLength <= int.MaxValue - RunPhaseProtection.TagLength )
            {
                maxLength += RunPhaseProtection.TagLength;
            }
            int messageLength;
            int lenSize = firstByte >> 6;
            if( lenSize == 0 )
            {
                // 1 byte length message. 
                messageLength = header.Span[1];
                if( messageLength > maxLength ) return IncomingMessage.Invalid;
                if( messageLength == 0 )
                {
                    // In the run phase even an empty keep-alive carries its tag, so a truly zero
                    // length frame can only be an unprotected one: it must not be accepted.
                    if( _protection != null ) return IncomingMessage.Invalid;
                    return protocolNumber == 0
                            ? ((firstByte & OutgoingMessage.IsControlFlag) != 0 ? IncomingMessage.EmptyAck : IncomingMessage.Empty)
                            : Throw.InvalidDataException<IncomingMessage>( $"Forbidden 0 length message received for protocol '{protocol}'." );
                }
                // The whole message (255 bytes max.) necessarily fits in the header.
                await exactReader( header.Slice( 2, messageLength ), cancellation ).ConfigureAwait( false );
                buffer.Advance( 2 + messageLength );
                if( _protection != null )
                {
                    var verified = VerifyAndCreate( protocol, buffer, prefixLength: 2 );
                    if( verified == null ) return IncomingMessage.Invalid;
                    // An authenticated keep-alive is a frame whose payload is empty once the tag is
                    // removed: it still had to be signed to get here.
                    if( verified.Message.IsEmpty && protocolNumber == 0 )
                    {
                        // Dispose() hands the sequence back to the factory: the finally must not
                        // return it a second time.
                        releaseBuffer = false;
                        verified.Dispose();
                        return (firstByte & OutgoingMessage.IsControlFlag) != 0 ? IncomingMessage.EmptyAck : IncomingMessage.Empty;
                    }
                    releaseBuffer = false;
                    return verified;
                }
                releaseBuffer = false;
                return new IncomingMessage( this, protocol, buffer, prefixLength: 2 );
            }
            // The length is on more than one byte. There must be at least 256 bytes
            // and we can fully handle the maximal 5 bytes prefix: we must now use the lenSize
            // following bytes (1 to 3) to know the message length.
            await exactReader( header.Slice( 2, 256 ), cancellation ).ConfigureAwait( false );
            // Now we can compute the message length: the 1 to 3 bytes are here.
            messageLength = (int)(BinaryPrimitives.ReadUInt32LittleEndian( header.Slice( 1 ).Span ) & (uint)((1ul << (lenSize + 1 << 3)) - 1));
            // If the resulting length is less than 256, it means that the data is simply invalid.
            if( messageLength < 256 || messageLength > maxLength )
            {
                return IncomingMessage.Invalid;
            }
            // We already read 2 + 256 = 258 bytes.
            buffer.Advance( 258 );
            // But we read 256 - lenSize bytes for the payload.
            messageLength -= 256 - lenSize;
            // What's left in our preallocated buffer?
            header = header.Slice( 258 );
            if( messageLength <= header.Length )
            {
                header = header.Slice( 0, messageLength );
                await exactReader( header, cancellation ).ConfigureAwait( false );
                buffer.Advance( header.Length );
                return Finish( protocol, buffer, lenSize + 2, ref releaseBuffer );
            }
            // There is more than the initial buffer. Fills it.
            await exactReader( header, cancellation ).ConfigureAwait( false );
            messageLength -= header.Length;
            buffer.Advance( header.Length );
            Throw.DebugAssert( "We totally filled the header but there's more to read.",
                               buffer.CurrentlyAvailableLength == 0 && messageLength > 0 );
            // Huge messages are uncommon. We choose to process buffers limited to 64K to avoid the LOH.
            while( messageLength >= 64 * 1024 )
            {
                await exactReader( buffer.GetMemory( 64 * 1024 ), cancellation ).ConfigureAwait( false );
                buffer.Advance( 64 * 1024 );
                messageLength -= 64 * 1024;
            }
            if( messageLength > 0 )
            {
                await exactReader( buffer.GetMemory( messageLength ).Slice( 0, messageLength ), cancellation ).ConfigureAwait( false );
                buffer.Advance( messageLength );
            }
            return Finish( protocol, buffer, lenSize + 2, ref releaseBuffer );
        }
        catch( OperationCanceledException ) when( cancellation.IsCancellationRequested )
        {
            return IncomingMessage.Canceled;
        }
        finally
        {
            if( releaseBuffer ) Release( buffer );
        }
    }

    /// <summary>
    /// Completes a fully read frame: verifies its tag when the run phase is protected.
    /// </summary>
    IncomingMessage Finish( MessageProtocol protocol, MutableSequence<byte> buffer, int prefixLength, ref bool releaseBuffer )
    {
        if( _protection != null )
        {
            var verified = VerifyAndCreate( protocol, buffer, prefixLength );
            if( verified == null ) return IncomingMessage.Invalid;
            releaseBuffer = false;
            return verified;
        }
        releaseBuffer = false;
        return new IncomingMessage( this, protocol, buffer, prefixLength );
    }

    MutableSequence<byte> GetBuffer()
    {
        return Interlocked.Exchange( ref _cachedOneBuffer, null ) ?? new MutableSequence<byte>();
    }

    internal void Release( MutableSequence<byte> buffer )
    {
        buffer.Clear();
        Interlocked.CompareExchange( ref _cachedOneBuffer, buffer, null );
    }

    /// <summary>
    /// Disposes any internal resource.
    /// </summary>
    public void Dispose()
    {
        Interlocked.Exchange( ref _cachedOneBuffer, null )?.Dispose();
    }

}
