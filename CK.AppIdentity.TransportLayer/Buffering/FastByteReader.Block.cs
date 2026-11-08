using CK.Core;

namespace CK.AppIdentity.TransportLayer;

public ref partial struct FastByteReader
{
    /// <summary>
    /// Gets whether the end of the sequence is reached: nothing more can be read.
    /// <para>
    /// In a block read by <see cref="ReadBlock"/>, this is the end of the block: a reader of a block written by an
    /// older writer finds no more data where newer fields would be.
    /// </para>
    /// </summary>
    public bool IsEnd => HeadOffset == _sequence.Length;

    /// <summary>
    /// Reads a length-prefixed block written by <see cref="FastByteWriter.BeginBlock"/> and
    /// <see cref="FastByteWriter.EndBlock(in FastByteBlock)"/>: returns a reader on the content of the block, and moves
    /// this reader after the block, whatever is read from the returned one.
    /// <para>
    /// The block's reader reads what it knows and ignores the rest: fields added at the end of a block by a newer writer
    /// are skipped.
    /// </para>
    /// </summary>
    /// <returns>A reader on the content of the block.</returns>
    public FastByteReader ReadBlock()
    {
        int length = ReadInt32();
        Throw.CheckData( "Invalid block length.", length >= 0 && length <= _sequence.Length - HeadOffset );
        var block = new FastByteReader( _sequence.Slice( HeadOffset, length ) );
        Skip( length );
        return block;
    }

    /// <summary>
    /// Skips bytes.
    /// </summary>
    /// <param name="count">The number of bytes to skip. Must be positive or zero.</param>
    public void Skip( long count )
    {
        Throw.CheckArgument( count >= 0 );
        while( true )
        {
            int available = _bufferSize - _bufferPos;
            if( count <= available )
            {
                _bufferPos += (int)count;
                return;
            }
            count -= available;
            _bufferPos = _bufferSize;
            MoveNext();
        }
    }
}
