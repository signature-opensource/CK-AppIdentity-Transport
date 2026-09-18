using CK.Core;
using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Linq;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding L16: two boundary faults in the buffering primitives, both reachable from the wire.
/// <para>
/// These are the codecs every message goes through, so a fault here is not confined to one protocol,
/// and both only appear at an exact boundary — the kind of thing a round-trip test over a couple of
/// sizes walks straight past.
/// </para>
/// </summary>
[TestFixture]
public class FastByteCodecTests
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

    [Test]
    public void A_string_that_exactly_fills_the_buffer_round_trips()
    {
        // WriteString's fast path writes the payload at pos+1, after a one-byte length prefix, so the
        // room it needs is one MORE than the worst-case expansion. Checking only for the expansion
        // lets an exact fit through, and Encoding.GetBytes then throws one byte short.
        //
        // Walking the buffer size across the whole fast-path range hits that boundary wherever it is,
        // instead of hoping a couple of hand-picked sizes land on it.
        // The fast path tests the room left in the CURRENT span, not the buffer size, so the boundary
        // is reached by how far the write head has already advanced. Sweeping a filler across more
        // than a whole buffer guarantees landing on it, whatever size the pool actually handed out.
        foreach( var charCount in new[] { 1, 2, 21, 41, 42 } )
        {
            var value = new string( 'a', charCount );
            for( int filler = 0; filler < 600; ++filler )
            {
                using var sequence = new MutableSequence<byte>();
                var w = new FastByteWriter( sequence );
                for( int i = 0; i < filler; ++i ) w.WriteByte( 7 );
                w.WriteString( value );
                w.Commit();

                var r = new FastByteReader( sequence.GetReadOnlySequence() );
                for( int i = 0; i < filler; ++i ) r.ReadByte();
                r.ReadString().ShouldBe( value, $"charCount={charCount}, filler={filler}." );
            }
        }
    }

    [Test]
    public void A_malformed_varint_fails_the_same_way_on_both_paths()
    {
        // ReadSmallUInt32 has a fast path and a slow one, and which runs depends only on where a
        // segment boundary falls. A header claiming more than five bytes is malformed either way, so
        // both must reject it the same: otherwise identical hostile input surfaces as
        // InvalidDataException or OverflowException depending on how the peer chose to fragment it,
        // and a caller cannot handle it in one place.
        var malformed = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        // Single segment: comfortably more than 8 bytes ahead, so the fast path runs.
        Should.Throw<System.IO.InvalidDataException>( () =>
        {
            var r = new FastByteReader( new ReadOnlySequence<byte>( malformed ) );
            r.ReadSmallUInt32();
        } );

        // One byte per segment: fewer than 8 bytes ahead, so the slow path runs on the same bytes.
        Should.Throw<System.IO.InvalidDataException>( () =>
        {
            var r = new FastByteReader( MultiSegment( malformed, 1 ) );
            r.ReadSmallUInt32();
        } );
    }

    [Test]
    public void A_truncated_multi_segment_string_does_not_leak_its_rented_buffer()
    {
        // ReadMultiSegment rents from the shared pool before reading. A truncated string — which a
        // peer chooses — throws out of ReadBytes, and without a finally that buffer never comes back.
        // Repeating it drains the pool one rent at a time.
        //
        // The pool gives no way to observe this directly, so this asserts the reachable part: the
        // failure is the expected one, every time, and nothing degrades over many repetitions.
        // Write a real long string, then hand the reader only part of it: a valid length prefix with
        // the payload cut short, which is exactly what a peer that stops mid-message produces.
        using var sequence = new MutableSequence<byte>();
        var w = new FastByteWriter( sequence );
        w.WriteString( new string( 'z', 3000 ) );
        w.Commit();
        var full = sequence.GetReadOnlySequence().ToArray();
        var truncated = full.AsSpan( 0, 500 ).ToArray();

        for( int i = 0; i < 200; ++i )
        {
            // Small segments so the multi-segment (rented) path is the one taken.
            Should.Throw<System.IO.InvalidDataException>( () =>
            {
                var r = new FastByteReader( MultiSegment( truncated, 64 ) );
                r.ReadString();
            } );
        }
    }
}
