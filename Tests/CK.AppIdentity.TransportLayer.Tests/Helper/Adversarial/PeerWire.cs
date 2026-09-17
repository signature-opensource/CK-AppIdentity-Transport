using System;
using System.Buffers.Binary;
using System.IO;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests.Adversarial;

/// <summary>
/// Framing for the adversarial peer: an <em>independent</em> implementation of the wire header
/// <c>[1 byte: lenSize(2b) | isControl(1b) | protocolNumber(3b)][1..4 bytes length][payload]</c>.
/// <para>
/// This deliberately does NOT call <see cref="IOutgoingMessage.WriteWireHeader"/> or
/// <see cref="IncomingMessageFactory"/>. An adversarial harness that reuses the production codec
/// inherits the production codec's bugs and cannot detect divergence — it would happily agree with
/// a broken implementation. <see cref="PeerWireTests"/> pins this implementation against the real
/// reader so the two are known to agree.
/// </para>
/// </summary>
static class PeerWire
{
    /// <summary>Protocol number of the "0 Protocol" on the wire.</summary>
    public const uint ZeroProtocolNumber = 0;

    /// <summary>Mirrors <c>OutgoingMessage.IsControlFlag</c> (which is internal).</summary>
    public const byte IsControlFlag = 0b00100000;

    /// <summary>Maximum header size: 1 flag byte + up to 4 length bytes.</summary>
    public const int MaxHeaderLength = 5;

    /// <summary>
    /// Writes the wire header into <paramref name="header"/> (which must be at least
    /// <see cref="MaxHeaderLength"/> long) and returns its length.
    /// </summary>
    public static int WriteHeader( Span<byte> header, uint protocolNumber, uint payloadLength, bool isControl = false )
    {
        if( header.Length < MaxHeaderLength ) throw new ArgumentException( "Header buffer too small.", nameof( header ) );
        if( protocolNumber > 7 ) throw new ArgumentOutOfRangeException( nameof( protocolNumber ) );
        // Log2(0) is 0, which yields a 1-byte length of 0: that is the "empty message" encoding.
        uint lenSize = (uint)BitOperations.Log2( payloadLength ) / 8;
        uint b = (lenSize << 6) | protocolNumber;
        if( isControl ) b |= IsControlFlag;
        header[0] = (byte)b;
        BinaryPrimitives.WriteUInt32LittleEndian( header.Slice( 1 ), payloadLength );
        return (int)lenSize + 2;
    }

    /// <summary>
    /// Builds a complete frame (header + payload) as a single array.
    /// </summary>
    public static byte[] Frame( ReadOnlySpan<byte> payload, uint protocolNumber = ZeroProtocolNumber, bool isControl = false )
    {
        Span<byte> header = stackalloc byte[MaxHeaderLength];
        int lenHeader = WriteHeader( header, protocolNumber, (uint)payload.Length, isControl );
        var r = new byte[lenHeader + payload.Length];
        header.Slice( 0, lenHeader ).CopyTo( r );
        payload.CopyTo( r.AsSpan( lenHeader ) );
        return r;
    }

    /// <summary>
    /// A frame read off the wire.
    /// </summary>
    public readonly record struct Frame2( uint ProtocolNumber, bool IsControl, byte[] Payload )
    {
        public bool IsZeroProtocol => ProtocolNumber == ZeroProtocolNumber;

        /// <summary>The Zero Protocol discriminator (first payload byte), or -1 when empty.</summary>
        public int Discriminator => Payload.Length == 0 ? -1 : Payload[0];
    }

    /// <summary>
    /// Reads one frame from a stream. Independent of the production reader.
    /// </summary>
    public static async Task<Frame2> ReadFrameAsync( Stream s, CancellationToken cancellation = default )
    {
        var head = new byte[2];
        await ReadExactlyAsync( s, head, cancellation );
        byte b0 = head[0];
        uint protocolNumber = (uint)(b0 & 0b00000111);
        bool isControl = (b0 & IsControlFlag) != 0;
        int lenSize = b0 >> 6;

        uint length;
        if( lenSize == 0 )
        {
            length = head[1];
        }
        else
        {
            // The length occupies lenSize+1 bytes starting at offset 1; we already hold the first.
            var lenBytes = new byte[4];
            lenBytes[0] = head[1];
            await ReadExactlyAsync( s, lenBytes.AsMemory( 1, lenSize ), cancellation );
            length = BinaryPrimitives.ReadUInt32LittleEndian( lenBytes );
        }
        var payload = new byte[length];
        if( length != 0 ) await ReadExactlyAsync( s, payload, cancellation );
        return new Frame2( protocolNumber, isControl, payload );
    }

    static async Task ReadExactlyAsync( Stream s, Memory<byte> buffer, CancellationToken cancellation )
    {
        int done = 0;
        while( done < buffer.Length )
        {
            int n = await s.ReadAsync( buffer.Slice( done ), cancellation );
            if( n == 0 ) throw new EndOfStreamException( $"Peer closed after {done}/{buffer.Length} bytes." );
            done += n;
        }
    }
}
