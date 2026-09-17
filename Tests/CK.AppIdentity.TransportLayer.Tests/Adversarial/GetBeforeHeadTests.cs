using NUnit.Framework;
using Shouldly;
using System;
using System.Buffers;
using System.Linq;
using System.Security.Cryptography;

namespace CK.AppIdentity.TransportLayer.Tests;

/// <summary>
/// Finding M2: <see cref="FastByteReader.GetBeforeHead"/> after the first segment.
/// <para>
/// <c>GetBeforeHead</c> is what the Zero Protocol hashes to verify a signature
/// (<c>ComputeHash( r.GetBeforeHead(), ... )</c>). Incoming messages are read into a first segment
/// of <see cref="IncomingMessageFactory.FirstSegmentLength"/> (4096) bytes and then continue into
/// further segments, so any handshake message larger than 4 KiB has its signature checked over
/// whatever this method returns. If it returns the wrong range, a perfectly legitimate peer fails
/// verification — and the failure only appears once a handshake payload grows past 4 KiB.
/// </para>
/// <para>
/// The audit could not execute this ("mechanism confirmed by reading; not executed", and no test
/// referenced <c>GetBeforeHead</c>). These tests execute it.
/// </para>
/// </summary>
[TestFixture]
public class GetBeforeHeadTests
{
    sealed class Seg : ReadOnlySequenceSegment<byte>
    {
        public Seg( ReadOnlyMemory<byte> memory, long runningIndex )
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }
        public Seg Append( ReadOnlyMemory<byte> memory )
        {
            var next = new Seg( memory, RunningIndex + Memory.Length );
            Next = next;
            return next;
        }
    }

    /// <summary>
    /// Builds a genuinely multi-segment sequence, independent of MutableSequence so that this test
    /// cannot be fooled by a bug in the buffer stack it is meant to exercise.
    /// </summary>
    static ReadOnlySequence<byte> MultiSegment( byte[] data, int segmentSize )
    {
        var first = new Seg( data.AsMemory( 0, Math.Min( segmentSize, data.Length ) ), 0 );
        var last = first;
        for( int o = segmentSize; o < data.Length; o += segmentSize )
        {
            last = last.Append( data.AsMemory( o, Math.Min( segmentSize, data.Length - o ) ) );
        }
        return new ReadOnlySequence<byte>( first, 0, last, last.Memory.Length );
    }

    [Test]
    public void MultiSegment_helper_builds_what_it_claims()
    {
        var data = RandomNumberGenerator.GetBytes( 10000 );
        var seq = MultiSegment( data, 4096 );
        seq.Length.ShouldBe( 10000 );
        seq.IsSingleSegment.ShouldBeFalse();
        seq.ToArray().ShouldBe( data );
        // 4096 + 4096 + 1808
        var lengths = new System.Collections.Generic.List<int>();
        foreach( var m in seq ) lengths.Add( m.Length );
        lengths.ShouldBe( new[] { 4096, 4096, 1808 } );
    }

    // Read counts chosen around the segment boundary: inside the first segment, exactly at it,
    // and past it — the transition is where the reader's position bookkeeping goes wrong.
    [TestCase( 10, 4096 )]
    [TestCase( 4095, 4096 )]
    [TestCase( 4096, 4096 )]
    [TestCase( 4097, 4096 )]
    [TestCase( 5000, 4096 )]
    [TestCase( 8192, 4096 )]
    [TestCase( 9000, 4096 )]
    [TestCase( 300, 256 )]
    [TestCase( 700, 256 )]
    public void GetBeforeHead_returns_exactly_what_was_read( int readCount, int segmentSize )
    {
        var data = RandomNumberGenerator.GetBytes( 10000 );
        var seq = MultiSegment( data, segmentSize );

        var r = new FastByteReader( seq );
        var consumed = r.ReadBytes( (uint)readCount );
        consumed.ShouldBe( data.AsSpan( 0, readCount ).ToArray(), "Sanity: the bytes read must be the first ones." );

        var before = r.GetBeforeHead();
        before.Length.ShouldBe( readCount,
            $"GetBeforeHead must cover exactly the {readCount} bytes consumed. This is the range the " +
            $"Zero Protocol hashes to verify a signature: if it is wrong, a legitimate peer is rejected." );
        before.ToArray().ShouldBe( data.AsSpan( 0, readCount ).ToArray() );
    }

    [Test]
    public void GetBeforeHead_is_consistent_with_GetAfterHead()
    {
        var data = RandomNumberGenerator.GetBytes( 10000 );
        var seq = MultiSegment( data, 4096 );

        var r = new FastByteReader( seq );
        r.ReadBytes( 5000 );

        var before = r.GetBeforeHead();
        var after = r.GetAfterHead();
        (before.Length + after.Length).ShouldBe( seq.Length,
            "The two halves must partition the sequence." );
        before.ToArray().Concat( after.ToArray() ).ToArray().ShouldBe( data );
    }

    [TestCase( 5000 )]
    [TestCase( 20000 )]
    [TestCase( 100000 )]
    public async System.Threading.Tasks.Task GetBeforeHead_is_correct_on_a_real_IncomingMessage_Async( int payloadLength )
    {
        // The segmentation above is synthetic. This one is the real thing: the production
        // IncomingMessageFactory reads into a 4 KiB first segment and then 64 KiB ones, which is
        // exactly the shape the Zero Protocol hashes over when it verifies a handshake signature.
        var dir = new MessageProtocolDirectoryService();
        dir.TryRegister( CK.Testing.MonitorTestHelper.TestHelper.Monitor, "Test", 0, out var protocol ).ShouldBeTrue();
        var map = MessageProtocolMap.Get( protocol );
        using var incoming = new IncomingMessageFactory( map );

        var payload = RandomNumberGenerator.GetBytes( payloadLength );
        var frame = Adversarial.PeerWire.Frame( payload, protocolNumber: 1 );
        int offset = 0;
        System.Threading.Tasks.ValueTask Reader( Memory<byte> m, System.Threading.CancellationToken t )
        {
            frame.AsSpan( offset, m.Length ).CopyTo( m.Span );
            offset += m.Length;
            return System.Threading.Tasks.ValueTask.CompletedTask;
        }

        using var message = await incoming.ReadAsync( Reader );
        message.IsValid.ShouldBeTrue();
        message.Message.IsSingleSegment.ShouldBeFalse( "A payload this size must span several segments." );

        // Read a prefix that crosses the first segment boundary and check the hashed range.
        // FastByteReader is a ref struct, so the work happens in a synchronous helper.
        // Must read PAST the 4 KiB first segment, otherwise the bug cannot show.
        int readCount = payloadLength - 500;
        readCount.ShouldBeGreaterThan( IncomingMessageFactory.FirstSegmentLength );
        CheckHead( message.Message, payload, readCount );

        static void CheckHead( ReadOnlySequence<byte> sequence, byte[] expected, int readCount )
        {
            var r = new FastByteReader( sequence );
            r.ReadBytes( (uint)readCount );
            var head = r.GetBeforeHead();
            head.Length.ShouldBe( readCount );
            head.ToArray().ShouldBe( expected.AsSpan( 0, readCount ).ToArray() );
        }
    }

    [Test]
    public void GetBeforeHead_is_correct_on_a_single_segment()
    {
        // Control: the single-segment case is the one that works today, and it is why nothing has
        // noticed — every handshake message so far fits in the 4 KiB first segment.
        var data = RandomNumberGenerator.GetBytes( 1000 );
        var seq = new ReadOnlySequence<byte>( data );

        var r = new FastByteReader( seq );
        r.ReadBytes( 400 );
        r.GetBeforeHead().ToArray().ShouldBe( data.AsSpan( 0, 400 ).ToArray() );
    }
}
