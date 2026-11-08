using CK.Core;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer.Tests;

[TestFixture]
public class FastByteBlockTests
{
    sealed class Seg : ReadOnlySequenceSegment<byte>
    {
        public Seg( ReadOnlyMemory<byte> memory, Seg? previous = null )
        {
            Memory = memory;
            if( previous != null )
            {
                RunningIndex = previous.RunningIndex + previous.Memory.Length;
                previous.Next = this;
            }
        }
    }

    static ReadOnlySequence<byte> MultiSegment( byte[] data, int segmentSize )
    {
        Seg? first = null, last = null;
        for( int o = 0; o < data.Length; o += segmentSize )
        {
            last = new Seg( data.AsMemory( o, Math.Min( segmentSize, data.Length - o ) ), last );
            first ??= last;
        }
        Throw.DebugAssert( first != null && last != null );
        return new ReadOnlySequence<byte>( first, 0, last, last.Memory.Length );
    }

    // A "newer" writer: an outer block with a name, an inner block with a number and a field that
    // older readers don't know, then a field after the inner block that they don't know either.
    static byte[] WriteNewer()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        w.WriteByte( 42 );
        var outer = w.BeginBlock();
        w.WriteString( "name" );
        var inner = w.BeginBlock();
        w.WriteInt32( 3712 );
        w.WriteString( "a newer field" );
        w.EndBlock( inner );
        w.WriteString( "another newer field" );
        w.EndBlock( outer );
        w.WriteByte( 43 );
        w.Commit();
        return sequence.GetReadOnlySequence().ToArray();
    }

    [TestCase( 0 )]
    [TestCase( 1 )]
    [TestCase( 2 )]
    [TestCase( 3 )]
    [TestCase( 7 )]
    public void an_older_reader_skips_what_it_doesnt_know( int segmentSize )
    {
        var data = WriteNewer();
        var r = new FastByteReader( segmentSize == 0 ? new ReadOnlySequence<byte>( data ) : MultiSegment( data, segmentSize ) );
        r.ReadByte().ShouldBe( (byte)42 );
        var outer = r.ReadBlock();
        outer.ReadString().ShouldBe( "name" );
        var inner = outer.ReadBlock();
        inner.ReadInt32().ShouldBe( 3712 );
        // The older reader stops here: the newer fields are skipped, in the inner block and in the outer one.
        r.ReadByte().ShouldBe( (byte)43 );
        r.IsEnd.ShouldBeTrue();
    }

    [Test]
    public void a_newer_reader_of_an_older_block_finds_its_end()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var b = w.BeginBlock();
        w.WriteString( "name" );
        w.EndBlock( b );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var block = r.ReadBlock();
        block.ReadString().ShouldBe( "name" );
        // A newer reader would read a field here: the block ends, the field has its default.
        block.IsEnd.ShouldBeTrue();
        r.IsEnd.ShouldBeTrue();
    }

    [Test]
    public void an_empty_block_is_valid()
    {
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var b = w.BeginBlock();
        w.EndBlock( b );
        w.WriteByte( 1 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        r.ReadBlock().IsEnd.ShouldBeTrue();
        r.ReadByte().ShouldBe( (byte)1 );
    }

    [Test]
    public void a_block_longer_than_the_data_is_refused()
    {
        var data = WriteNewer();
        // The outer block's length (after the first byte) claims more than what remains.
        data[1] = 0xFF;
        Should.Throw<System.IO.InvalidDataException>( () =>
        {
            var r = new FastByteReader( new ReadOnlySequence<byte>( data ) );
            r.ReadByte();
            r.ReadBlock();
        } );
    }

    [Test]
    public void blocks_span_many_buffers()
    {
        // A block bigger than a buffer: its length is reserved in one segment and written once the
        // content has moved to others.
        var big = new string( 'x', 200_000 );
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        var b = w.BeginBlock();
        w.WriteString( big );
        w.WriteInt32( 1 );
        w.EndBlock( b );
        w.WriteInt32( 2 );
        w.Commit();

        var r = new FastByteReader( sequence.GetReadOnlySequence() );
        var block = r.ReadBlock();
        block.ReadString().ShouldBe( big );
        block.ReadInt32().ShouldBe( 1 );
        block.IsEnd.ShouldBeTrue();
        r.ReadInt32().ShouldBe( 2 );
        r.IsEnd.ShouldBeTrue();
    }
}
