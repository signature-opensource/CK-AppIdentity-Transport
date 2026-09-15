using CK.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Provides basic write function to a <see cref="MutableSequence{T}"/> of bytes.
/// <see cref="Commit"/> MUST be called at the end of the write session.
/// <para>
/// This writer is tied to a <see cref="MutableSequence{T}"/> instead of a more general <see cref="IBufferWriter{T}"/>.
/// This avoids virtcalls and to enable the already written bytes to be accessible from a FastByteWriter (with <see cref="MutableSequence{T}.GetReadOnlySequence(int)"/>)
/// without relying on external knwoledge.
/// </para>
/// <para>
/// This FastByteWriter is not a "general purpose" writer: it is tailored to only work with MutableSequence and this fits our needs.
/// If targeting other <see cref="IBufferWriter{T}"/> is important we could extract this in a FastByteWriter&lt;T&gt; where T : IBufferWriter and
/// compose this FastByteWriter with it and relay the calls (that should be elided at compile time) but at this time it seems useless.
/// </para>
/// </summary>
public ref partial struct FastByteWriter
{
    readonly MutableSequence<byte> _output;
    Span<byte> _currentSpan;
    int _bufferPos;
    long _totalWritten;
    Encoder? _utf8Encoder;
    // This writer will not allocate contiguous buffers bigger than 64 KiB
    // if it can, but if EnsureContiguous or Allocate are called with a bigger
    // requested size, it will of course satisfy the demand (this is why this
    // is a just hint).
    internal const int MaxSegmentSizeHint = 64 * 1024;

    /// <summary>
    /// Initializes a new FastByteWriter on a <see cref="MutableSequence{T}"/> of bytes
    /// starting at its beginning.
    /// </summary>
    /// <param name="output">The written sequence.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public FastByteWriter( MutableSequence<byte> output )
    {
        _output = output;
        _currentSpan = _output.GetSpan();
        _bufferPos = 0;
        _totalWritten = 0;
        _utf8Encoder = null;
    }

    /// <summary>
    /// Gets the bytes written so far. <see cref="Commit()"/> should be called
    /// before accessing to these already written bytes.
    /// </summary>
    public readonly MutableSequence<byte> Output => _output;

    /// <summary>
    /// Gets the total number of bytes written so far.
    /// </summary>
    public long TotalWritten => _totalWritten;

    /// <summary>
    /// Gets the current writable span.
    /// </summary>
    /// <value>The current writable span.</value>
    public Span<byte> WritableSpan
    {
        [MethodImpl( MethodImplOptions.AggressiveInlining )]
        get => _currentSpan.Slice( _bufferPos );
    }

    /// <summary>
    /// Advance the write position in the current span.
    /// </summary>
    /// <param name="length">The number of bytes to advance write position by.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void AdvanceSpan( int length ) => _bufferPos += length;

    /// <summary>
    /// Commit the currently written buffers.
    /// </summary>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void Commit()
    {
        _totalWritten += _bufferPos;
        _output.Advance( _bufferPos );
        _currentSpan = default;
        _bufferPos = 0;
    }

    /// <summary>
    /// Gets the already written sequence. See <see cref="MutableSequence{T}.GetReadOnlySequence()"/>.
    /// <para>
    /// This calls <see cref="Commit"/> first.
    /// </para>
    /// </summary>
    /// <returns>The data written so far.</returns>
    public ReadOnlySequence<byte> GetBeforeHead()
    {
        Commit();
        var s = _output.GetReadOnlySequence();
        // Nominal case (sequence Length computation is fast): we are not
        // rewriting an already filled MutableSequence.
        return s.Length == _totalWritten
                                ? s
                                : s.Slice( s.Start, _totalWritten );
    }


    /// <summary>
    /// Calls <see cref="Commit"/> and reserves a block of contiguous bytes
    /// that can be written later. The initial content of this memory is not specified.
    /// <para>
    /// After this call, <see cref="Output"/> ends with this reserved memory.
    /// </para>
    /// </summary>
    /// <param name="length">The block's length. Must be positive.</param>
    /// <returns>The reserved memory.</returns>
    public Memory<byte> ReserveMemory( int length )
    {
        Throw.CheckArgument( length > 0 );
        Commit();
        var m = _output.GetMemory( length );
        _totalWritten += length;
        _output.Advance( length );
        return m.Slice( 0, length );
    }

    /// <summary>
    /// Ensures that there are at least <paramref name="length"/> contiguous bytes available to be written.
    /// </summary>
    /// <param name="length">The number of contiguous bytes to ensure.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void EnsureContiguous( int length )
    {
        // The current buffer is adequate.
        if( _bufferPos + length < _currentSpan.Length )
        {
            return;
        }
        // The current buffer is inadequate, allocate another.
        Allocate( length );
    }

    /// <summary>
    /// Allocates buffer space for the specified number of bytes.
    /// This commits the current written data and acquires a new one.
    /// You may want to use <see cref="EnsureContiguous(int)"/> rather than this method.
    /// </summary>
    /// <param name="sizeHint">The number of bytes to reserve.</param>
    [MethodImpl( MethodImplOptions.NoInlining )]
    public void Allocate( int sizeHint )
    {
        _totalWritten += _bufferPos;
        _output.Advance( _bufferPos );
        _currentSpan = _output.GetSpan( sizeHint );
        _bufferPos = 0;
    }

    /// <summary>
    /// Writes the specified bytes as-is.
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteBytes( scoped ReadOnlySpan<byte> value )
    {
        // Fast path, try copying to the current buffer.
        var destination = WritableSpan;
        if( (uint)value.Length <= (uint)destination.Length )
        {
            value.CopyTo( destination );
            _bufferPos += value.Length;
        }
        else
        {
            WriteMultiSegment( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteMultiSegment( scoped ReadOnlySpan<byte> input )
    {
        while( true )
        {
            // Write as much as possible/necessary into the current segment.
            var span = WritableSpan;
            var writeSize = Math.Min( span.Length, input.Length );
            input[..writeSize].CopyTo( span );
            _bufferPos += writeSize;

            input = input[writeSize..];

            if( input.Length == 0 )
            {
                return;
            }

            // The current segment is full but there is more to write.
            Allocate( Math.Min( input.Length, MaxSegmentSizeHint ) );
        }
    }

    /// <summary>
    /// Writes a 1 or 0 value <see cref="byte"/>.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteBool( bool value ) => WriteByte( value ? (byte)1 : (byte)0 );

    /// <summary>
    /// Writes a <see cref="sbyte"/>.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteSByte( sbyte value ) => WriteByte( (byte)value );

    /// <summary>
    /// Writes a <see cref="byte"/>.
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteByte( byte value )
    {
        nuint bufferPos = (uint)_bufferPos;
        if( (uint)bufferPos < (uint)_currentSpan.Length )
        {
            // https://github.com/dotnet/runtime/issues/72004
            Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), bufferPos ) = value;
            _bufferPos = (int)(uint)bufferPos + 1;
        }
        else
        {
            WriteByteSlow( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteByteSlow( byte value )
    {
        Allocate( 1 );
        _currentSpan[0] = value;
        _bufferPos = 1;
    }

    /// <summary>
    /// Writes a <see cref="short"/>.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteInt16( short value ) => WriteUInt16( (ushort)value );

    /// <summary>
    /// Writes a <see cref="ushort"/> (2 byes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteUInt16( ushort value )
    {
        nuint pos = (uint)_bufferPos;
        int newPos = (int)(uint)pos + sizeof( ushort );
        if( (uint)newPos <= (uint)_currentSpan.Length )
        {
            _bufferPos = newPos;
            if( !BitConverter.IsLittleEndian ) value = BinaryPrimitives.ReverseEndianness( value );
            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos ), value );
        }
        else
        {
            WriteUInt16Slow( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteUInt16Slow( ushort value )
    {
        Allocate( sizeof( ushort ) );
        BinaryPrimitives.WriteUInt16LittleEndian( _currentSpan, value );
        _bufferPos = sizeof( ushort );
    }

    /// <summary>
    /// Writes a <see cref="int"/> (4 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteInt32( int value ) => WriteUInt32( (uint)value );

    /// <summary>
    /// Writes a <see cref="long"/> (8 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteInt64( long value ) => WriteUInt64( (ulong)value );

    /// <summary>
    /// Writes a <see cref="uint"/> (4 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteUInt32( uint value )
    {
        nuint pos = (uint)_bufferPos;
        int newPos = (int)(uint)pos + sizeof( uint );
        if( (uint)newPos <= (uint)_currentSpan.Length )
        {
            _bufferPos = newPos;
            if( !BitConverter.IsLittleEndian ) value = BinaryPrimitives.ReverseEndianness( value );
            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos ), value );
        }
        else
        {
            WriteUInt32Slow( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteUInt32Slow( uint value )
    {
        Allocate( sizeof( uint ) );
        BinaryPrimitives.WriteUInt32LittleEndian( _currentSpan, value );
        _bufferPos = sizeof( uint );
    }

    /// <summary>
    /// Writes a <see cref="ulong"/> (8 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteUInt64( ulong value )
    {
        nuint pos = (uint)_bufferPos;
        int newPos = (int)(uint)pos + sizeof( ulong );
        if( (uint)newPos <= (uint)_currentSpan.Length )
        {
            _bufferPos = newPos;
            if( !BitConverter.IsLittleEndian ) value = BinaryPrimitives.ReverseEndianness( value );
            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos ), value );
        }
        else
        {
            WriteUInt64Slow( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteUInt64Slow( ulong value )
    {
        Allocate( sizeof( ulong ) );
        BinaryPrimitives.WriteUInt64LittleEndian( _currentSpan, value );
        _bufferPos = sizeof( ulong );
    }

    /// <summary>
    /// Writes a <see cref="uint"/> as a variable-width integer (1 to 5 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteSmallUInt32( uint value )
    {
        var neededBytes = (int)((uint)BitOperations.Log2( value ) / 7);

        ulong lower = (((ulong)value << 1) + 1) << neededBytes;

        nuint pos = (uint)_bufferPos;
        if( (uint)pos + sizeof( ulong ) <= (uint)_currentSpan.Length )
        {
            _bufferPos = (int)(uint)pos + neededBytes + 1;
            if( !BitConverter.IsLittleEndian ) lower = BinaryPrimitives.ReverseEndianness( lower );
            Unsafe.WriteUnaligned( ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos ), lower );
        }
        else
        {
            WriteSmallUInt56Slow( lower );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteSmallUInt56Slow( ulong lower )
    {
        Allocate( sizeof( ulong ) );

        var neededBytes = BitOperations.TrailingZeroCount( (uint)lower ) + 1;
        BinaryPrimitives.WriteUInt64LittleEndian( _currentSpan, lower );
        _bufferPos = neededBytes;
    }

    /// <summary>
    /// Writes a (hopefully) small integer value using ZigZag encoding.
    /// The smaller the absolute value is, the best it is.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteSmallInt16( short value ) => WriteSmallUInt32( EncodeZigZag( value ) );

    /// <summary>
    /// Writes a (hopefully) small integer value using ZigZag encoding.
    /// The smaller the absolute value is, the best it is.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteSmallInt32( int value ) => WriteSmallUInt32( EncodeZigZag( value ) );

    /// <summary>
    /// Writes a (hopefully) small signed long value using ZigZag encoding.
    /// The smaller the absolute value is, the best it is.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteSmallInt64( long value ) => WriteSmallUInt64( EncodeZigZag( value ) );


    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    static uint EncodeZigZag( int value ) => (uint)((value << 1) ^ (value >> 31));

    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    static ulong EncodeZigZag( long value ) => (ulong)((value << 1) ^ (value >> 63));

    /// <summary>
    /// Writes the provided <see cref="ulong"/> to the output buffer as a variable-width integer.
    /// </summary>
    /// <param name="value">The value.</param>
    [MethodImpl( MethodImplOptions.AggressiveInlining )]
    public void WriteSmallUInt64( ulong value )
    {
        nuint pos = (uint)_bufferPos;
        // Since this method writes a ulong plus a ushort worth of bytes unconditionally, ensure that there is sufficient space.
        if( (uint)pos + sizeof( ulong ) + sizeof( ushort ) <= (uint)_currentSpan.Length )
        {
            var neededBytes = (int)((uint)BitOperations.Log2( value ) / 7);
            _bufferPos = (int)(uint)pos + neededBytes + 1;

            ulong lower = ((value << 1) + 1) << neededBytes;

            ref var writeHead = ref Unsafe.Add( ref MemoryMarshal.GetReference( _currentSpan ), pos );
            if( !BitConverter.IsLittleEndian ) lower = BinaryPrimitives.ReverseEndianness( lower );
            Unsafe.WriteUnaligned( ref writeHead, lower );

            // Write the 2 byte overflow unconditionally
            var upper = value >> (63 - neededBytes);
            writeHead = ref Unsafe.Add( ref writeHead, sizeof( ulong ) );
            if( !BitConverter.IsLittleEndian ) upper = BinaryPrimitives.ReverseEndianness( (ushort)upper );
            Unsafe.WriteUnaligned( ref writeHead, (ushort)upper );
        }
        else
        {
            WriteSmallUInt64Slow( value );
        }
    }

    [MethodImpl( MethodImplOptions.NoInlining )]
    void WriteSmallUInt64Slow( ulong value )
    {
        Allocate( sizeof( ulong ) + sizeof( ushort ) );

        var neededBytes = (int)((uint)BitOperations.Log2( value ) / 7);
        _bufferPos = neededBytes + 1;

        ulong lower = ((value << 1) + 1) << neededBytes;
        BinaryPrimitives.WriteUInt64LittleEndian( _currentSpan, lower );

        // Write the 2 byte overflow unconditionally
        var upper = value >> (63 - neededBytes);
        BinaryPrimitives.WriteUInt16LittleEndian( _currentSpan.Slice( sizeof( ulong ) ), (ushort)upper );
    }

    /// <summary>
    /// Writes a <see cref="Half"/>.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteHalf( Half value ) => WriteUInt16( BitConverter.HalfToUInt16Bits( value ) );

    /// <summary>
    /// Writes a float.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteSingle( float value ) => WriteUInt32( BitConverter.SingleToUInt32Bits( value ) );

    /// <summary>
    /// Writes a double.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteDouble( double value ) => WriteUInt64( BitConverter.DoubleToUInt64Bits( value ) );

    /// <summary>
    /// Writes a character that can be a surrogate (an invalid <see cref="Rune"/>): this
    /// simply calls <see cref="WriteSmallUInt32(uint)"/>.
    /// </summary>
    /// <param name="c">The character to write.</param>
    public void WriteChar( char c ) => WriteSmallUInt32( c );

    /// <summary>
    /// Writes a length prefixed string.
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteString( string value )
    {
        Throw.CheckNotNullArgument( value );
        var sLen = value.Length;
        if( sLen == 0 )
        {
            WriteByte( 1 );
            return;
        }
        if( sLen <= 42 )
        {
            // Max expansion is 3 bytes per char.
            // Strings smaller than 42 characters always fit in 128 bytes (including the one byte prefix):
            // this is our fast path... if there are 128 bytes available. 
            Throw.DebugAssert( 42 * 3 == 126 );
            nuint pos = (uint)_bufferPos;
            if( (uint)pos + sLen * 3 <= (uint)_currentSpan.Length )
            {
                int actualByteCount = Encoding.UTF8.GetBytes( value, _currentSpan.Slice( (int)pos + 1 ) );
                _currentSpan[(int)pos] = (byte)((actualByteCount << 1) + 1);
                _bufferPos = (int)(uint)pos + actualByteCount + 1;
                return;
            }
        }
        WriteStringSlow( value );
    }

    void WriteStringSlow( string value )
    {
        // No other choice here: we must compute the final bytes length
        // to be able to write it before the content.
        var numBytes = Encoding.UTF8.GetByteCount( value );
        WriteSmallUInt32( (uint)numBytes );
        // If the string is not that big, skips the encoder.
        if( numBytes <= 256 )
        {
            EnsureContiguous( numBytes );
            AdvanceSpan( Encoding.UTF8.GetBytes( value, WritableSpan ) );
        }
        else
        {
            // We need an encoder instance.
            var encoder = _utf8Encoder ??= Encoding.UTF8.GetEncoder();
            var input = value.AsSpan();
            int remainingBytes = numBytes;

            // Fills the available space and allocates more segments.
            while( true )
            {
                encoder.Convert( input, WritableSpan, true, out var charsUsed, out var bytesWritten, out var completed );
                AdvanceSpan( bytesWritten );

                if( completed )
                {
                    Throw.DebugAssert( charsUsed == input.Length && bytesWritten == remainingBytes );
                    break;
                }

                remainingBytes -= bytesWritten;
                input = input[charsUsed..];

                Allocate( Math.Min( remainingBytes, MaxSegmentSizeHint ) );
            }
        }

    }

    /// <summary>
    /// Writes a <see cref="DateTime"/> (8 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteDateTime( DateTime value ) => WriteInt64( value.ToBinary() );

    /// <summary>
    /// Writes a <see cref="TimeSpan"/> (8 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteTimeSpan( TimeSpan value ) => WriteInt64( value.Ticks );

    /// <summary>
    /// Writes a <see cref="DateTimeOffset"/> (10 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteDateTimeOffset( DateTimeOffset value )
    {
        WriteInt64( value.DateTime.ToBinary() );
        WriteInt16( (short)value.Offset.TotalMinutes );
    }

    /// <summary>
    /// Writes a <see cref="Guid"/> (16 bytes).
    /// </summary>
    /// <param name="value">The value.</param>
    public void WriteGuid( in Guid value )
    {
        const int Width = 16;

        if( BitConverter.IsLittleEndian )
        {
            WriteBytes( MemoryMarshal.AsBytes( new ReadOnlySpan<Guid>( in value ) ) );
        }
        else
        {
            EnsureContiguous( Width );
            value.TryWriteBytes( WritableSpan );
            AdvanceSpan( Width );
        }
    }

    /// <summary>
    /// Writes an <see cref="Index"/>.
    /// </summary>
    /// <param name="index">The index.</param>
    public void WriteIndex( Index index ) => WriteSmallInt32( index.IsFromEnd ? ~index.Value : index.Value );

    /// <summary>
    /// Writes a <see cref="Range"/>.
    /// </summary>
    /// <param name="range">The value to write.</param>
    public void WriteRange( Range range )
    {
        WriteIndex( range.Start );
        WriteIndex( range.End );
    }

}

