using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace CK.AppIdentity.TransportLayer;

public ref partial struct FastByteReader
{
    ReadOnlySpan<byte> _currentSpan;
    SequencePosition _nextSequencePosition;
    int _bufferPos;
    int _bufferSize;
    readonly ReadOnlySequence<byte> _sequence;

    public FastByteReader( ReadOnlySequence<byte> sequence )
    {
        _nextSequencePosition = sequence.Start;
        _currentSpan = sequence.First.Span;
        _bufferPos = 0;
        _bufferSize = _currentSpan.Length;
        _sequence = sequence;
    }

    /// <summary>
    /// Gets the currently read sequence.
    /// </summary>
    /// <returns>The data read so far.</returns>
    public ReadOnlySequence<byte> GetBeforeHead()
    {
        var start = _sequence.GetPosition( _bufferPos, _nextSequencePosition );
        return _sequence.Slice( 0, start );
    }

    /// <summary>
    /// Gets the current remainder of the sequence.
    /// </summary>
    /// <returns>The remainder.</returns>
    public ReadOnlySequence<byte> GetAfterHead()
    {
        var start = _sequence.GetPosition( _bufferPos, _nextSequencePosition );
        return _sequence.Slice( start );
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void MoveNext()
    {
        // If this is the first call to MoveNext then nextSequencePosition is invalid and must be moved to the second position.
        if( _nextSequencePosition.Equals( _sequence.Start ) )
        {
            _ = _sequence.TryGet( ref _nextSequencePosition, out _ );
        }

        if( !_sequence.TryGet( ref _nextSequencePosition, out var memory ) )
        {
            _currentSpan = memory.Span;
            Throw.InvalidDataException( "End of Sequence reached." );
        }
        _currentSpan = memory.Span;
        _bufferPos = 0;
        _bufferSize = _currentSpan.Length;
    }

    /// <summary>
    /// Reads an array of bytes from the input.
    /// </summary>
    /// <param name="count">The length of the array to read.</param>
    /// <returns>The array.</returns>
    public byte[] ReadBytes( uint count )
    {
        if( count == 0 ) return Array.Empty<byte>();
        var bytes = new byte[count];
        ReadBytes( bytes.AsSpan() );
        return bytes;
    }

    /// <summary>
    /// Fills <paramref name="destination"/> with bytes read from the input.
    /// </summary>
    /// <param name="destination">The destination.</param>
    public void ReadBytes( scoped Span<byte> destination )
    {
        if( _bufferPos + destination.Length <= _bufferSize )
        {
            _currentSpan.Slice( _bufferPos, destination.Length ).CopyTo( destination );
            _bufferPos += destination.Length;
            return;
        }

        ReadBytesMultiSegment( destination );
    }

    void ReadBytesMultiSegment( scoped Span<byte> dest )
    {
        while( true )
        {
            var writeSize = Math.Min( dest.Length, _currentSpan.Length - _bufferPos );
            _currentSpan.Slice( _bufferPos, writeSize ).CopyTo( dest );
            _bufferPos += writeSize;
            dest = dest.Slice( writeSize );
            if( dest.Length == 0 ) break;
            MoveNext();
        }
    }

    /// <summary>
    /// Tries to read the specified number of bytes directly from the current segment.
    /// </summary>
    /// <param name="length">The length.</param>
    /// <param name="bytes">The bytes which were read.</param>
    /// <returns>True if the specified number of bytes can be read from the current segment, false otherwise.</returns>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public bool TryReadBytes( int length, out ReadOnlySpan<byte> bytes )
    {
        if( _bufferPos + length <= _bufferSize )
        {
            bytes = _currentSpan.Slice( _bufferPos, length );
            _bufferPos += length;
            return true;
        }

        bytes = default;
        return false;
    }

    /// <summary>
    /// Reads a signed byte.
    /// </summary>
    /// <returns>The signed byte which was read.</returns>
    public sbyte ReadSByte() => (sbyte)ReadByte();

    /// <summary>
    /// Reads a byte.
    /// </summary>
    /// <returns>The byte which was read.</returns>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public byte ReadByte()
    {
        var pos = _bufferPos;
        if( (uint)pos < (uint)_currentSpan.Length )
        {
            // https://github.com/dotnet/runtime/issues/72004
            var result = Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), (uint)pos );
            _bufferPos = pos + 1;
            return result;
        }

        return ReadByteSlow( ref this );
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    static byte ReadByteSlow( ref FastByteReader reader )
    {
        reader.MoveNext();
        return reader._currentSpan[reader._bufferPos++];
    }

    /// <summary>
    /// Reads a boolean value.
    /// </summary>
    /// <returns>The read value.</returns>
    public bool ReadBool() => ReadByte() == 1;

    /// <summary>
    /// Reads a <see cref="short"/>.
    /// </summary>
    /// <returns>The read value.</returns>
    public short ReadInt16() => (short)ReadUInt16();

    /// <summary>
    /// Reads a <see cref="ushort"/>.
    /// </summary>
    /// <returns>The read value.</returns>
    public ushort ReadUInt16()
    {
        const int width = 2;
        if( _bufferPos + width > _bufferSize )
        {
            return ReadSlower( ref this );
        }

        var result = BinaryPrimitives.ReadUInt16LittleEndian( _currentSpan.Slice( _bufferPos, width ) );
        _bufferPos += width;
        return result;

        static ushort ReadSlower( ref FastByteReader r )
        {
            uint b1 = r.ReadByte();
            uint b2 = r.ReadByte();
            return (ushort)(b1 | (b2 << 8));
        }
    }

    /// <summary>
    /// Reads an <see cref="int"/> from the input.
    /// </summary>
    /// <returns>The <see cref="int"/> which was read.</returns>
    public int ReadInt32() => (int)ReadUInt32();

    /// <summary>
    /// Reads a <see cref="uint"/> from the input.
    /// </summary>
    /// <returns>The <see cref="uint"/> which was read.</returns>
    public uint ReadUInt32()
    {
        const int width = 4;
        if( _bufferPos + width > _bufferSize )
        {
            return ReadSlower( ref this );
        }

        var result = BinaryPrimitives.ReadUInt32LittleEndian( _currentSpan.Slice( _bufferPos, width ) );
        _bufferPos += width;
        return result;

        static uint ReadSlower( ref FastByteReader r )
        {
            uint b1 = r.ReadByte();
            uint b2 = r.ReadByte();
            uint b3 = r.ReadByte();
            uint b4 = r.ReadByte();

            return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
        }
    }

    /// <summary>
    /// Reads a <see cref="long"/> from the input.
    /// </summary>
    /// <returns>The <see cref="long"/> which was read.</returns>
    public long ReadInt64() => (long)ReadUInt64();

    /// <summary>
    /// Reads a <see cref="ulong"/> from the input.
    /// </summary>
    /// <returns>The <see cref="ulong"/> which was read.</returns>
    public ulong ReadUInt64()
    {
        const int width = 8;
        if( _bufferPos + width > _bufferSize )
        {
            return ReadSlower( ref this );
        }
        var result = BinaryPrimitives.ReadUInt64LittleEndian( _currentSpan.Slice( _bufferPos, width ) );
        _bufferPos += width;
        return result;

        static ulong ReadSlower( ref FastByteReader r )
        {
            ulong b1 = r.ReadByte();
            ulong b2 = r.ReadByte();
            ulong b3 = r.ReadByte();
            ulong b4 = r.ReadByte();
            ulong b5 = r.ReadByte();
            ulong b6 = r.ReadByte();
            ulong b7 = r.ReadByte();
            ulong b8 = r.ReadByte();

            return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)
                    | (b5 << 32) | (b6 << 40) | (b7 << 48) | (b8 << 56);
        }
    }

    /// <summary>
    /// Reads a variable-width <see cref="uint"/> from the input.
    /// </summary>
    /// <returns>The <see cref="uint"/> which was read.</returns>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public uint ReadSmallUInt32()
    {
        var pos = _bufferPos;

        if( !BitConverter.IsLittleEndian || pos + 8 > _currentSpan.Length )
        {
            return ReadSmallUInt32Slow();
        }

        // The number of zeros in the msb position dictates the number of bytes to be read.
        // Up to a maximum of 5 for a 32bit integer.
        ref byte readHead = ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos );

        ulong result = Unsafe.ReadUnaligned<ulong>( ref readHead );
        var bytesNeeded = BitOperations.TrailingZeroCount( (uint)result ) + 1;
        if( bytesNeeded > 5 ) Throw.InvalidDataException();
        _bufferPos = pos + bytesNeeded;
        result &= (1UL << (bytesNeeded * 8)) - 1;
        result >>= bytesNeeded;
        return checked((uint)result);
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    uint ReadSmallUInt32Slow()
    {
        var header = ReadByte();
        var numBytes = BitOperations.TrailingZeroCount( 0x0100U | header ) + 1;
        // Widen to a ulong for the 5-byte case
        ulong result = header;
        // Read additional bytes as needed
        var shiftBy = 8;
        var i = numBytes;
        while( --i > 0 )
        {
            result |= (ulong)ReadByte() << shiftBy;
            shiftBy += 8;
        }
        result >>= numBytes;
        return checked((uint)result);
    }

    /// <summary>
    /// Reads a signed byte using ZigZag encoding.
    /// The smaller the absolute value of the value, the best it is.
    /// </summary>
    /// <returns>The read value.</returns>
    public short ReadSmallInt16() => ZigZagDecode( checked((ushort)ReadSmallUInt32()) );

    /// <summary>
    /// Reads a signed long integer using ZigZag encoding.
    /// The smaller the absolute value of the value, the best it is.
    /// </summary>
    /// <returns>The read value.</returns>
    public int ReadSmallInt32() => ZigZagDecode( ReadSmallUInt32() );

    /// <summary>
    /// Reads a signed long integer using ZigZag encoding.
    /// The smaller the absolute value of the value, the best it is.
    /// </summary>
    /// <returns>The read value.</returns>
    public long ReadSmallInt64() => ZigZagDecode( ReadUInt64() );

    const short Int16Msb = unchecked((short)0x8000);
    const int Int32Msb = unchecked((int)0x80000000);
    const long Int64Msb = unchecked((long)0x8000000000000000);

    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    static short ZigZagDecode( ushort encoded )
    {
        var value = (short)encoded;
        return (short)(-(value & 0x01) ^ ((short)(value >> 1) & ~Int16Msb));
    }

    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    static int ZigZagDecode( uint encoded )
    {
        var value = (int)encoded;
        return -(value & 0x01) ^ ((value >> 1) & ~Int32Msb);
    }

    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    static long ZigZagDecode( ulong encoded )
    {
        var value = (long)encoded;
        return -(value & 0x01L) ^ ((value >> 1) & ~Int64Msb);
    }

    /// <summary>
    /// Reads a variable-width <see cref="ulong"/> from the input.
    /// </summary>
    /// <returns>The <see cref="ulong"/> which was read.</returns>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public ulong ReadSmallUInt64()
    {
        var pos = _bufferPos;
        if( !BitConverter.IsLittleEndian || pos + 10 > _currentSpan.Length )
        {
            return ReadSmallUInt64Slow();
        }

        // The number of zeros in the msb position dictates the number of bytes to be read.
        // Up to a maximum of 5 for a 32bit integer.
        ref byte readHead = ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos );

        ulong result = Unsafe.ReadUnaligned<ulong>( ref readHead );

        var bytesNeeded = BitOperations.TrailingZeroCount( result ) + 1;
        result >>= bytesNeeded;
        _bufferPos += bytesNeeded;

        ushort upper = Unsafe.ReadUnaligned<ushort>( ref Unsafe.Add( ref readHead, sizeof( ulong ) ) );
        result |= ((ulong)upper) << (64 - bytesNeeded);

        // Mask off invalid data
        var fullWidthReadMask = ~((ulong)bytesNeeded - 10 + 1);
        var mask = ((1UL << (bytesNeeded * 7)) - 1) | fullWidthReadMask;
        result &= mask;

        return result;
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    ulong ReadSmallUInt64Slow()
    {
        var header = ReadByte();
        var numBytes = BitOperations.TrailingZeroCount( 0x0100U | header ) + 1;

        // Widen to a ulong for the 5-byte case
        ulong result = header;

        // Read additional bytes as needed
        if( numBytes < 9 )
        {
            var shiftBy = 8;
            var i = numBytes;
            while( --i > 0 )
            {
                result |= (ulong)ReadByte() << shiftBy;
                shiftBy += 8;
            }

            result >>= numBytes;
            return result;
        }
        else
        {
            result |= (ulong)ReadByte() << 8;

            // If there was more than one byte worth of trailing zeros, read again now that we have more data.
            numBytes = BitOperations.TrailingZeroCount( result ) + 1;

            if( numBytes == 9 )
            {
                result |= (ulong)ReadByte() << 16;
                result |= (ulong)ReadByte() << 24;
                result |= (ulong)ReadByte() << 32;

                result |= (ulong)ReadByte() << 40;
                result |= (ulong)ReadByte() << 48;
                result |= (ulong)ReadByte() << 56;
                result >>= 9;

                var upper = (ushort)ReadByte();
                result |= ((ulong)upper) << (64 - 9);
                return result;
            }
            else if( numBytes == 10 )
            {
                result |= (ulong)ReadByte() << 16;
                result |= (ulong)ReadByte() << 24;
                result |= (ulong)ReadByte() << 32;

                result |= (ulong)ReadByte() << 40;
                result |= (ulong)ReadByte() << 48;
                result |= (ulong)ReadByte() << 56;
                result >>= 10;

                var upper = (ushort)(ReadByte() | (ushort)(ReadByte() << 8));
                result |= ((ulong)upper) << (64 - 10);
                return result;
            }
        }

        return Throw.ArgumentOutOfRangeException<ulong>( "value" );
    }

    /// <summary>
    /// Reads a <see cref="Half"/>.
    /// </summary>
    /// <returns>The read value.</returns>
    public Half ReadHalf() => BitConverter.UInt16BitsToHalf( ReadUInt16() );

    /// <summary>
    /// Reads a <see cref="float"/>.
    /// </summary>
    /// <returns>The read value.</returns>
    public float ReadSingle() => BitConverter.UInt32BitsToSingle( ReadUInt32() );

    /// <summary>
    /// Reads a <see cref="double"/>.
    /// </summary>
    /// <returns>The read value.</returns>
    public double ReadDouble() => BitConverter.UInt64BitsToDouble( ReadUInt64() );

    /// <summary>
    /// Reads a character written by <see cref="FastByteWriter.WriteChar(char)"/>.
    /// This character can be a surrogate point.
    /// </summary>
    /// <returns>The read value.</returns>
    public char ReadChar() => (char)ReadSmallUInt32();

    /// <summary>
    /// Reads a string written by <see cref="FastByteWriter.WriteString(string)"/>.
    /// </summary>
    /// <returns>The string.</returns>
    public string ReadString()
    {
        int len = (int)ReadSmallUInt32();
        if( len == 0 ) return String.Empty;
        if( TryReadBytes( len, out var span ) )
            return Encoding.UTF8.GetString( span );
        return ReadMultiSegment( ref this, len );
    }

    /// <summary>
    /// Reads a string written by <see cref="FastByteWriter.WriteString(string)"/>
    /// with a length constraint: a <see cref="System.IO.InvalidDataException"/> is thrown if the string
    /// is longer than <paramref name="maxLength"/>.
    /// </summary>
    /// <param name="maxLength">Maximal length of the string.</param>
    /// <returns>The string.</returns>
    public string ReadString( int maxLength )
    {
        Throw.CheckOutOfRangeArgument( maxLength >= 0 );
        int len = (int)ReadSmallUInt32();
        if( len == 0 ) return String.Empty;
        Throw.CheckData( len <= maxLength );
        if( TryReadBytes( len, out var span ) )
            return Encoding.UTF8.GetString( span );
        return ReadMultiSegment( ref this, len );
    }

    static string ReadMultiSegment( ref FastByteReader reader, int len )
    {
        var array = ArrayPool<byte>.Shared.Rent( len );
        var span = array.AsSpan( 0, len );
        reader.ReadBytes( span );
        var res = Encoding.UTF8.GetString( span );
        ArrayPool<byte>.Shared.Return( array );
        return res;
    }

    /// <summary>
    /// Reads a DateTime written by <see cref="FastByteWriter.WriteDateTime(DateTime)"/>.
    /// </summary>
    /// <returns>The value.</returns>
    public DateTime ReadDateTime() => DateTime.FromBinary( ReadInt64() );

    /// <summary>
    /// Reads a TimeSpan written by <see cref="FastByteWriter.WriteTimeSpan(TimeSpan)"/>.
    /// </summary>
    /// <returns>The value.</returns>
    public TimeSpan ReadTimeSpan() => TimeSpan.FromTicks( ReadInt64() );

    /// <summary>
    /// Reads a DateTimeOffset written by <see cref="FastByteWriter.WriteDateTimeOffset(DateTimeOffset)"/>.
    /// </summary>
    /// <returns>The value.</returns>
    public DateTimeOffset ReadDateTimeOffset() => new DateTimeOffset( ReadDateTime(), TimeSpan.FromMinutes( ReadInt16() ) );

    /// <summary>
    /// Reads a Guid written by <see cref="FastByteWriter.WriteGuid(in Guid)"/>.
    /// </summary>
    /// <returns>The value.</returns>
    public Guid ReadGuid()
    {

#if NET7_0_OR_GREATER
        Unsafe.SkipInit(out Guid res);
        var bytes = MemoryMarshal.AsBytes(new Span<Guid>(ref res));
        ReadBytes(bytes);

        if (BitConverter.IsLittleEndian)
            return res;

        return new Guid(bytes);
#else
        const int Width = 16;
        if( TryReadBytes( Width, out var readOnly ) )
        {
            return new Guid( readOnly );
        }

        Span<byte> bytes = stackalloc byte[Width];
        ReadBytes( bytes );
        return new Guid( bytes );
#endif
    }

    /// <summary>
    /// Reads an <see cref="Index"/>.
    /// </summary>
    /// <returns>The index.</returns>
    public Index ReadIndex()
    {
        int v = ReadSmallInt32();
        return v < 0 ? Index.FromEnd( ~v ) : Index.FromStart( v );
    }

    /// <summary>
    /// Reads a <see cref="Range"/>.
    /// </summary>
    /// <returns>The range.</returns>
    public Range ReadRange() => new Range( ReadIndex(), ReadIndex() );

}

