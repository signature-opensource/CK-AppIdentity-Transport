using CK.Core;
using System;
using System.Buffers.Binary;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// A length-prefixed block opened by <see cref="FastByteWriter.BeginBlock"/> and closed by
/// <see cref="FastByteWriter.EndBlock(in FastByteBlock)"/>.
/// </summary>
public readonly struct FastByteBlock
{
    internal readonly Memory<byte> _length;
    internal readonly long _start;

    internal FastByteBlock( Memory<byte> length, long start )
    {
        _length = length;
        _start = start;
    }
}

public ref partial struct FastByteWriter
{
    /// <summary>
    /// Opens a length-prefixed block: its length (4 bytes, little endian) is written by
    /// <see cref="EndBlock(in FastByteBlock)"/>. Blocks can be nested.
    /// <para>
    /// A block is read by <see cref="FastByteReader.ReadBlock"/>: the reader reads what it knows of the block and
    /// ignores the rest. This is how a structure can be extended (new fields at the end of its block) without
    /// breaking its readers.
    /// </para>
    /// </summary>
    /// <returns>The block to close.</returns>
    public FastByteBlock BeginBlock()
    {
        var length = ReserveMemory( sizeof( int ) );
        // ReserveMemory commits: the content of the block starts at the total written so far.
        return new FastByteBlock( length, _totalWritten );
    }

    /// <summary>
    /// Closes a block opened by <see cref="BeginBlock"/>: writes the length of its content.
    /// </summary>
    /// <param name="block">The block to close.</param>
    public void EndBlock( in FastByteBlock block )
    {
        Throw.CheckArgument( !block._length.IsEmpty );
        long length = _totalWritten + _bufferPos - block._start;
        Throw.CheckState( "The block must be closed by the writer that opened it, after its content.", length >= 0 && length <= int.MaxValue );
        BinaryPrimitives.WriteInt32LittleEndian( block._length.Span, (int)length );
    }
}
